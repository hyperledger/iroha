//! Complete canonical bytes from the original frozen State journals.
//!
//! This owner retains original-pool frames and exact no-op/absent undo entries.
//! Canonical key order is byte order, independent of native map ordering. A retry
//! borrows the same StateBlock and retains completed fields and row prefixes.
//! There is no root, proof, finality or publication capability in this module.
//! TODO: select the keyed engine and consume this exact cut in the existing
//! StatePublication owner; authenticate the pre-tail cut and deterministic tail
//! during atomic restore before replacing the current World-only commitment.

use super::{Canonical, Field, Role, STATE_FIELDS, Schema, V1_LAYOUT, find_identity, visit};
use crate::state::{CellField, StateBlock, StorageField, block_field::AggregatePublication};
use iroha_allocation::{AllocationBudget, ChargedBuffer, ChargedBufferError};
use mv::{Key, Value};
use norito::codec::Encode;
use std::io::Write;

mod cells;
mod encoding;
mod membership;
mod policies;
mod world;
use encoding::Frame;

/// Local encoding allowances. Refusal does not change transaction validity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::state) struct CaptureLimits {
    /// Complete table/cell descriptor capacity.
    pub max_fields: usize,
    /// Aggregate current and undo rows, including empty-valued preimages.
    pub max_rows: usize,
    /// Maximum individual canonical key or value frame.
    pub max_payload_bytes: usize,
    /// Aggregate retained frame bytes in this attempt.
    pub max_total_payload_bytes: usize,
    /// Aggregate admitted physical source-row inspections for each traversal.
    /// Includes skipped retained prefixes and each filtered membership scan;
    /// frame encoding bytes and policy-internal collection work have separate bounds.
    pub max_source_visits: usize,
}

/// Exact source or local encoding refusal; no partial cut is a successful result.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CaptureError {
    /// The exact original owner has not completed its required frozen phase.
    #[error("original State is not completely frozen")]
    NotFrozen,
    /// Original target, predecessor, source allocation or cardinality differs.
    #[error("canonical State source changed: {0}")]
    Changed(&'static str),
    /// A source names no canonical table or cell in the closed registry.
    #[error("unexpected canonical State field: {0}")]
    Unexpected(&'static str),
    /// A complete result would omit a declared canonical table or cell.
    #[error("missing canonical State field: {0}")]
    Missing(&'static str),
    /// A source visited one field twice or encoded two keys identically.
    #[error("duplicate canonical State field or key: {0}")]
    Duplicate(&'static str),
    /// Field kind or explicit first-release layout is incomplete or inconsistent.
    #[error("canonical State field schema differs: {0}")]
    Schema(&'static str),
    /// Whole-field cardinalities exceed this attempt's local work or row bound.
    #[error("original State capture exceeds local field or row admission")]
    CountLimit,
    /// Complete canonical payloads exceed a local frame or aggregate byte bound.
    #[error("original State capture exceeds local payload admission")]
    PayloadLimit,
    /// An immutable encoder produced different bytes on its funded write pass.
    #[error("original canonical encoder changed between measure and write")]
    EncodingChanged,
    /// Preserve the original pool release observation or exact allocator refusal.
    #[error(transparent)]
    Allocation(#[from] ChargedBufferError),
    /// Fixed-layout Norito refused the exact original payload.
    #[error("canonical State encoding failed: {0}")]
    Codec(norito::core::Error),
    /// Bounded hashing or writing failed without returning a partial frame.
    #[error("canonical State encoding I/O failed: {0}")]
    EncodingIo(std::io::Error),
    /// A source-owner semantic projection refused the exact original values.
    #[error("original State source validation failed: {0}")]
    Source(String),
    /// Existing paired semantic admission or original source custody is incomplete.
    #[error("original Musubi group is unavailable: {0:?}")]
    Musubi(crate::state::publication::RetainedMusubiGroupReadError),
}

/// A key and its exact optional payload. `None` is an absent undo preimage.
struct Row {
    key: Frame,
    value: Option<Frame>,
}

/// Exact original field identity, never a caller-asserted commitment.
#[derive(Debug, PartialEq, Eq)]
pub(in crate::state) enum SourceIdentity {
    /// Opaque original target, predecessor and acquisition mode.
    Journal(mv::BlockPublicationIdentity),
    /// Exact prepared membership allocation and predecessor.
    Membership(crate::state::storage_transactions::TransactionsPublicationSurface),
    /// Immutable policy captured in the original StateBlock's enclosing borrow.
    Policy(usize),
}

/// Complete field with its physical original undo, including same-value touches.
struct FieldBytes {
    seen: bool,
    replacement: bool,
    id: &'static str,
    source: SourceIdentity,
    current: ChargedBuffer<Row>,
    undo: ChargedBuffer<Row>,
}

/// Borrowed change from the original journal, in canonical key order.
pub(in crate::state) struct Change<'a> {
    /// Fixed-layout canonical key bytes; empty for a cell.
    pub key: &'a [u8],
    /// Exact original preimage/absence; replacement rows follow an explicit clear.
    pub before: Option<&'a [u8]>,
    /// Exact successor value, or explicit deletion.
    pub after: Option<&'a [u8]>,
}

/// A completed row prefix and partially encoded next row survive local refusal.
struct PendingField {
    replacement: bool,
    id: &'static str,
    source: SourceIdentity,
    current_count: usize,
    undo_count: usize,
    current: Option<ChargedBuffer<Row>>,
    undo: Option<ChargedBuffer<Row>>,
    key: Option<Frame>,
    value: Option<Frame>,
}

/// Internal sink shared only with the concrete original source owners.
/// It cannot finish without the complete registry and has no public constructor.
pub(crate) struct Collector {
    budget: AllocationBudget,
    limits: CaptureLimits,
    fields: ChargedBuffer<FieldBytes>,
    pending: Option<PendingField>,
    payload_bytes: usize,
    rows: usize,
    source_visits: usize,
}

impl Collector {
    fn new(budget: AllocationBudget, limits: CaptureLimits) -> Result<Self, CaptureError> {
        let mut count = 0;
        let mut schema_error = None;
        let mut duplicate = None;
        visit(STATE_FIELDS, &mut |field| {
            if super::count_identity(STATE_FIELDS, field.id) != 1 {
                duplicate.get_or_insert(field.id);
            }
            let mut check = |schema| {
                let accepted = match schema {
                    Schema::Norito { layout, .. } => layout == V1_LAYOUT,
                    Schema::Semantic {
                        identity,
                        encoder,
                        layout,
                    } => layout == V1_LAYOUT && !identity.is_empty() && !encoder.is_empty(),
                    Schema::Required { .. } => false,
                };
                if !accepted {
                    schema_error.get_or_insert(field.id);
                }
            };
            match field.role {
                Role::Canonical(Canonical::Table { key, value }) => {
                    count += 1;
                    check(key);
                    check(value);
                }
                Role::Canonical(Canonical::Cell(schema)) => {
                    count += 1;
                    check(schema);
                }
                _ => {}
            }
        });
        if let Some(id) = duplicate {
            return Err(CaptureError::Duplicate(id));
        }
        if let Some(id) = schema_error {
            return Err(CaptureError::Schema(id));
        }
        if count > limits.max_fields {
            return Err(CaptureError::CountLimit);
        }
        Ok(Self {
            fields: ChargedBuffer::new(count, &budget)?,
            budget,
            limits,
            pending: None,
            payload_bytes: 0,
            rows: 0,
            source_visits: 0,
        })
    }

    /// The exact original State pool; semantic owners must fund any scratch here.
    pub(crate) fn budget(&self) -> &AllocationBudget {
        &self.budget
    }

    /// Admit complete original source scans before inspection. A failed scan can
    /// consume less than its admitted count; retries start a fresh traversal while
    /// retaining all completed bytes and exact source identities.
    fn admit_source_visits(&mut self, count: usize) -> Result<(), CaptureError> {
        let visits = self
            .source_visits
            .checked_add(count)
            .ok_or(CaptureError::CountLimit)?;
        if visits > self.limits.max_source_visits {
            return Err(CaptureError::CountLimit);
        }
        self.source_visits = visits;
        Ok(())
    }

    fn start_traversal(&mut self) {
        self.source_visits = 0;
        for field in self.fields.as_mut_slice() {
            field.seen = false;
        }
    }

    fn canonical(id: &'static str) -> Result<Option<&'static Field>, CaptureError> {
        let field = find_identity(STATE_FIELDS, id).ok_or(CaptureError::Unexpected(id))?;
        Ok(matches!(
            field.role,
            Role::Canonical(Canonical::Table { .. } | Canonical::Cell(_))
        )
        .then_some(field))
    }

    /// Start or resume the same exact original field. Completed fields are not encoded twice.
    fn begin(
        &mut self,
        id: &'static str,
        source: SourceIdentity,
        current: usize,
        undo: usize,
    ) -> Result<bool, CaptureError> {
        if Self::canonical(id)?.is_none() {
            return Err(CaptureError::Unexpected(id));
        }
        if let Some(done) = self
            .fields
            .as_mut_slice()
            .iter_mut()
            .find(|field| field.id == id)
        {
            if done.seen {
                return Err(CaptureError::Duplicate(id));
            }
            done.seen = true;
            if done.source != source
                || done.current.as_slice().len() != current
                || done.undo.as_slice().len() != undo
            {
                return Err(CaptureError::Changed(id));
            }
            return Ok(false);
        }
        if let Some(pending) = self.pending.as_ref() {
            if pending.id != id
                || pending.source != source
                || pending.current_count != current
                || pending.undo_count != undo
            {
                return Err(CaptureError::Changed(id));
            }
        } else {
            let rows = current
                .checked_add(undo)
                .and_then(|n| n.checked_add(self.rows))
                .ok_or(CaptureError::CountLimit)?;
            if rows > self.limits.max_rows {
                return Err(CaptureError::CountLimit);
            }
            self.rows = rows;
            self.pending = Some(PendingField {
                replacement: false,
                id,
                source,
                current_count: current,
                undo_count: undo,
                current: None,
                undo: None,
                key: None,
                value: None,
            });
        }
        let pending = self.pending.as_mut().expect("pending original field");
        if pending.current.is_none() {
            pending.current = Some(ChargedBuffer::new(current, &self.budget)?);
        }
        if pending.undo.is_none() {
            pending.undo = Some(ChargedBuffer::new(undo, &self.budget)?);
        }
        Ok(true)
    }

    fn retained(&self, undo: bool) -> usize {
        let field = self.pending.as_ref().expect("pending original field");
        let rows = if undo { &field.undo } else { &field.current };
        rows.as_ref().map_or(0, |rows| rows.as_slice().len())
    }

    fn frame(
        &mut self,
        encode: impl Fn(&mut dyn Write) -> Result<(), norito::core::Error>,
    ) -> Result<Frame, CaptureError> {
        let remaining = self
            .limits
            .max_total_payload_bytes
            .checked_sub(self.payload_bytes)
            .ok_or(CaptureError::PayloadLimit)?;
        let frame = Frame::from_writer(
            self.limits.max_payload_bytes.min(remaining),
            &self.budget,
            encode,
        )?;
        self.payload_bytes += frame.bytes().len();
        Ok(frame)
    }

    fn row(
        &mut self,
        undo: bool,
        key: impl Fn(&mut dyn Write) -> Result<(), norito::core::Error>,
        value: Option<impl Fn(&mut dyn Write) -> Result<(), norito::core::Error>>,
    ) -> Result<(), CaptureError> {
        if self
            .pending
            .as_ref()
            .expect("pending original field")
            .key
            .is_none()
        {
            let frame = self.frame(key)?;
            self.pending.as_mut().expect("pending original field").key = Some(frame);
        }
        if let Some(value) = value {
            if self
                .pending
                .as_ref()
                .expect("pending original field")
                .value
                .is_none()
            {
                let frame = self.frame(value)?;
                self.pending.as_mut().expect("pending original field").value = Some(frame);
            }
        }
        let pending = self.pending.as_mut().expect("pending original field");
        let row = Row {
            key: pending.key.take().expect("retained key"),
            value: pending.value.take(),
        };
        let rows = if undo {
            &mut pending.undo
        } else {
            &mut pending.current
        };
        rows.as_mut()
            .expect("admitted row backing")
            .try_push(row)
            .map_err(|_| CaptureError::Changed(pending.id))
    }

    fn finish_field(&mut self) -> Result<(), CaptureError> {
        let pending = self.pending.as_mut().expect("pending original field");
        for (rows, expected) in [
            (&mut pending.current, pending.current_count),
            (&mut pending.undo, pending.undo_count),
        ] {
            let rows = rows.as_mut().expect("admitted field backing");
            if rows.as_slice().len() != expected {
                return Err(CaptureError::Changed(pending.id));
            }
            rows.as_mut_slice()
                .sort_unstable_by(|a, b| a.key.bytes().cmp(b.key.bytes()));
            if rows
                .as_slice()
                .windows(2)
                .any(|pair| pair[0].key.bytes() == pair[1].key.bytes())
            {
                return Err(CaptureError::Duplicate(pending.id));
            }
        }
        let pending = self.pending.take().expect("completed field");
        self.fields
            .try_push(FieldBytes {
                seen: true,
                replacement: pending.replacement,
                id: pending.id,
                source: pending.source,
                current: pending.current.expect("complete current rows"),
                undo: pending.undo.expect("complete undo rows"),
            })
            .map_err(|field| CaptureError::Duplicate(field.id))
    }

    /// Skip a completed original policy before constructing temporary projection scratch.
    /// A successful skip counts as this pass's one visit; callers must not emit it again.
    pub(in crate::state) fn already_captured(
        &mut self,
        id: &'static str,
        source: &SourceIdentity,
    ) -> Result<bool, CaptureError> {
        let Some(done) = self
            .fields
            .as_mut_slice()
            .iter_mut()
            .find(|field| field.id == id)
        else {
            return Ok(false);
        };
        if &done.source != source {
            return Err(CaptureError::Changed(id));
        }
        if done.seen {
            return Err(CaptureError::Duplicate(id));
        }
        done.seen = true;
        Ok(true)
    }

    /// Borrowed semantic storage; the concrete owning module supplies its exact encoder.
    pub(crate) fn storage<K: Key + Encode, V: Value, M: mv::storage::StorageMode<K, V>>(
        &mut self,
        id: &'static str,
        storage: &StorageField<'_, K, V, M>,
        expected: &mv::storage::Storage<K, V, M>,
        mode: mv::BlockMode,
        encode: impl Fn(&V, &mut dyn Write) -> Result<(), norito::core::Error>,
    ) -> Result<(), CaptureError> {
        let Some(field) = Self::canonical(id)? else {
            return Ok(());
        };
        if !matches!(field.role, Role::Canonical(Canonical::Table { .. })) {
            return Err(CaptureError::Schema(id));
        }
        let images = storage.frozen_images().ok_or(CaptureError::NotFrozen)?;
        if !images.belongs_to(expected)
            || images.mode() != mode
            || storage.retained_read_matches_current(expected) != Some(true)
        {
            return Err(CaptureError::Changed(id));
        }
        let current = images.current_entries();
        let undo = images.undo_entries();
        if !self.begin(
            id,
            SourceIdentity::Journal(images.publication_identity()),
            current.len(),
            undo.len(),
        )? {
            return Ok(());
        }
        // Native iterators still inspect skipped retained prefixes on a retry.
        self.admit_source_visits(
            current
                .len()
                .checked_add(undo.len())
                .ok_or(CaptureError::CountLimit)?,
        )?;
        for (key, value) in current.skip(self.retained(false)) {
            self.row(
                false,
                |writer| bare(key, writer),
                Some(|writer: &mut dyn Write| encode(value, writer)),
            )?;
        }
        for (key, value) in undo.skip(self.retained(true)) {
            self.row(
                true,
                |writer| bare(key, writer),
                value.as_ref().map(|value| {
                    let encode = &encode;
                    move |writer: &mut dyn Write| encode(value, writer)
                }),
            )?;
        }
        self.finish_field()
    }

    /// Borrow one original MV cell, preserving a touched equal-value preimage.
    pub(crate) fn cell<V: Value, C: Send + Sync + 'static>(
        &mut self,
        id: &'static str,
        cell: &CellField<'_, V, C>,
        expected: &mv::cell::Cell<V, C>,
        mode: mv::BlockMode,
        encode: impl Fn(&V, &mut dyn Write) -> Result<(), norito::core::Error>,
    ) -> Result<(), CaptureError> {
        if Self::canonical(id)?.is_none() {
            return Ok(());
        }
        let (current, before) = cell.frozen_values().ok_or(CaptureError::NotFrozen)?;
        if !cell.belongs_to(expected)
            || cell.mode() != mode
            || cell.retained_read_matches_current(expected) != Some(true)
        {
            return Err(CaptureError::Changed(id));
        }
        self.projected_cell(
            id,
            SourceIdentity::Journal(cell.publication_identity()),
            cell.touched_value().is_some(),
            |writer| encode(current, writer),
            |writer| encode(before, writer),
        )
    }

    /// Project a cell from a concrete immutable original owner; no State lookup is permitted.
    pub(in crate::state) fn projected_cell(
        &mut self,
        id: &'static str,
        source: SourceIdentity,
        touched: bool,
        current: impl Fn(&mut dyn Write) -> Result<(), norito::core::Error>,
        before: impl Fn(&mut dyn Write) -> Result<(), norito::core::Error>,
    ) -> Result<(), CaptureError> {
        if !matches!(
            Self::canonical(id)?.map(|field| field.role),
            Some(Role::Canonical(Canonical::Cell(_)))
        ) {
            return Err(CaptureError::Schema(id));
        }
        if !self.begin(id, source, 1, usize::from(touched))? {
            return Ok(());
        }
        let current_missing = self.retained(false) == 0;
        let before_missing = touched && self.retained(true) == 0;
        self.admit_source_visits(usize::from(current_missing) + usize::from(before_missing))?;
        if current_missing {
            self.row(false, |_| Ok(()), Some(current))?;
        }
        if before_missing {
            self.row(true, |_| Ok(()), Some(before))?;
        }
        self.finish_field()
    }

    fn require_complete(&mut self) -> Result<(), CaptureError> {
        if self.pending.is_some() {
            return Err(CaptureError::NotFrozen);
        }
        let mut missing = None;
        visit(STATE_FIELDS, &mut |field| {
            if matches!(
                field.role,
                Role::Canonical(Canonical::Table { .. } | Canonical::Cell(_))
            ) && !self
                .fields
                .as_slice()
                .iter()
                .any(|encoded| encoded.id == field.id && encoded.seen)
            {
                missing.get_or_insert(field.id);
            }
        });
        if let Some(id) = missing {
            return Err(CaptureError::Missing(id));
        }
        self.fields
            .as_mut_slice()
            .sort_unstable_by(|a, b| a.id.as_bytes().cmp(b.id.as_bytes()));
        Ok(())
    }
}

/// Encode the exact V1 bare layout. Never select a decoder or ambient fallback.
pub(crate) fn bare<T: Encode>(
    value: &T,
    writer: &mut dyn Write,
) -> Result<(), norito::core::Error> {
    let mut writer = writer;
    norito::codec::encode_adaptive_into(value, &mut writer).map(|_| ())
}

/// Failed visitor work remains provisional and retains the consumer's exact error.
#[derive(Debug, thiserror::Error)]
pub(in crate::state) enum VisitError<E> {
    /// No complete source is available to this visitor.
    #[error(transparent)]
    Source(#[from] CaptureError),
    /// The original consumer could not retain or process the next operation.
    #[error("original State byte consumer refused: {0}")]
    Consumer(E),
}

/// Same-original-cut byte retention. Borrowing forbids replacement of its sources.
pub(in crate::state) struct OriginalCut<'block, 'state> {
    block: &'block StateBlock<'state>,
    collector: Collector,
    complete: bool,
}

impl<'block, 'state> OriginalCut<'block, 'state> {
    /// Retain only a completely frozen original whose grouped sources are checked.
    pub(in crate::state) fn new(
        block: &'block StateBlock<'state>,
        limits: CaptureLimits,
    ) -> Result<Self, CaptureError> {
        let fields = block.fields.as_ref().ok_or(CaptureError::NotFrozen)?;
        if fields.world.publication != AggregatePublication::Frozen {
            return Err(CaptureError::NotFrozen);
        }
        block
            .original_musubi_bytes_ready()
            .map_err(CaptureError::Musubi)?;
        Ok(Self {
            block,
            collector: Collector::new(fields.state_ref.ivm_execution_budget.clone(), limits)?,
            complete: false,
        })
    }

    /// Advance only the original borrowed journals; completed fields survive refusal.
    pub(in crate::state) fn advance(&mut self) -> Result<(), CaptureError> {
        self.block
            .original_musubi_bytes_ready()
            .map_err(CaptureError::Musubi)?;
        // Recheck every exact original target even after all bytes were retained.
        // The retained prefixes are reused, never recaptured after target drift.
        self.complete = false;
        self.collector.start_traversal();
        world::append(self.block, &mut self.collector)?;
        cells::append(self.block, &mut self.collector)?;
        policies::append(
            self.block.fields.as_ref().ok_or(CaptureError::NotFrozen)?,
            &mut self.collector,
        )?;
        membership::append(self.block, &mut self.collector)?;
        self.collector.require_complete()?;
        self.complete = true;
        Ok(())
    }

    /// Visit complete field identities and canonical rows, including empty tables.
    /// A consumer refusal stops immediately; no partially delivered stream is complete.
    pub(in crate::state) fn visit<E>(
        &mut self,
        mut field: impl FnMut(&'static str, usize) -> Result<(), E>,
        mut row: impl FnMut(&'static str, &[u8], &[u8]) -> Result<(), E>,
    ) -> Result<(), VisitError<E>> {
        if !self.complete {
            return Err(CaptureError::NotFrozen.into());
        }
        self.advance()?;
        for value in self.collector.fields.as_slice() {
            field(value.id, value.current.as_slice().len()).map_err(VisitError::Consumer)?;
            for item in value.current.as_slice() {
                row(
                    value.id,
                    item.key.bytes(),
                    item.value.as_ref().expect("current payload").bytes(),
                )
                .map_err(VisitError::Consumer)?;
            }
        }
        Ok(())
    }

    /// Visit every original journal touch once, preserving absent and equal preimages.
    /// Membership invokes `replace_table` before all its rows, including when empty.
    /// Those insertions describe the cleared table, never an invented old preimage.
    /// Consumers retain provisional work and publish only after the whole visit succeeds.
    pub(in crate::state) fn changes<E>(
        &mut self,
        mut replace_table: impl FnMut(&'static str) -> Result<(), E>,
        mut visit: impl FnMut(&'static str, Change<'_>) -> Result<(), E>,
    ) -> Result<(), VisitError<E>> {
        if !self.complete {
            return Err(CaptureError::NotFrozen.into());
        }
        self.advance()?;
        for field in self.collector.fields.as_slice() {
            if field.replacement {
                replace_table(field.id).map_err(VisitError::Consumer)?;
                for row in field.current.as_slice() {
                    visit(
                        field.id,
                        Change {
                            key: row.key.bytes(),
                            before: None,
                            after: row.value.as_ref().map(Frame::bytes),
                        },
                    )
                    .map_err(VisitError::Consumer)?;
                }
                continue;
            }
            for undo in field.undo.as_slice() {
                let after = field
                    .current
                    .as_slice()
                    .binary_search_by(|row| row.key.bytes().cmp(undo.key.bytes()))
                    .ok()
                    .and_then(|index| field.current.as_slice()[index].value.as_ref());
                visit(
                    field.id,
                    Change {
                        key: undo.key.bytes(),
                        before: undo.value.as_ref().map(Frame::bytes),
                        after: after.map(Frame::bytes),
                    },
                )
                .map_err(VisitError::Consumer)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
