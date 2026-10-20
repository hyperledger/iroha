//! Exact proof-status membership from two retained native source images.
//!
//! Only the existing stored-key/status projection is checked here. This does
//! not validate proof contents, grant finalized authority, or change which
//! verification statuses may be retained.

use super::*;
use crate::state::authority_registry::original_images::RawStorageImages;
use iroha_data_model::proof::{ProofId, ProofRecord, ProofStatus};
use std::cmp::Ordering;

const INDEX: &str = "world.proofs_by_status";
const STATUSES: [ProofStatus; 3] = [
    ProofStatus::Submitted,
    ProofStatus::Verified,
    ProofStatus::Rejected,
];

/// Original proof records and the exact status lookup retained through encoding.
pub(in super::super) struct CheckedProofRecords<'world> {
    world: &'world World,
    rows: CommittedStorageView<'world, ProofId, ProofRecord>,
    index: CommittedStorageView<'world, (ProofStatus, ProofId), ()>,
}

impl<'world> CheckedProofRecords<'world> {
    /// Check both complete images with bounded allocation-free borrowed scans.
    pub(in super::super) fn capture(
        world: &'world World,
        max_work: u64,
    ) -> Result<Self, GroupedOwnershipError> {
        let checked = Self::retain(world)?;
        let result = checked.validate(&mut Work(max_work));
        checked.finish_validation(result)
    }

    fn retain(world: &'world World) -> Result<Self, GroupedOwnershipError> {
        Ok(Self {
            world,
            rows: world.proofs.try_committed_view_nonblocking()?,
            index: world.proofs_by_status.try_committed_view_nonblocking()?,
        })
    }

    fn validate(&self, work: &mut Work) -> Result<(), GroupedOwnershipError> {
        validate(&self.rows, &self.index, work)
    }

    fn finish_validation(
        self,
        result: Result<(), GroupedOwnershipError>,
    ) -> Result<Self, GroupedOwnershipError> {
        if !self.matches_current()? {
            return Err(PublicationPreparationError::Changed.into());
        }
        result?;
        Ok(self)
    }

    /// Borrow exactly the canonical reader whose status membership was checked.
    pub(in super::super) fn rows(&self) -> &CommittedStorageView<'world, ProofId, ProofRecord> {
        &self.rows
    }

    /// Observe both original owners after validation, errors and row encoding.
    pub(in super::super) fn matches_current(&self) -> Result<bool, GroupedOwnershipError> {
        let rows_current = self.rows.try_matches_current(&self.world.proofs)?;
        let index_current = self
            .index
            .try_matches_current(&self.world.proofs_by_status)?;
        Ok(rows_current && index_current)
    }
}

/// Check the same exact both-image status relation over retained native originals.
///
/// Callers must retain and authenticate both original source owners independently.
/// This checks the stored-key/status inverse only; proof contents, verifier admission
/// and the separate proof-tag relation are not established by this result.
pub(in crate::state) fn validate_original_proofs(
    rows: &impl RawStorageImages<ProofId, ProofRecord>,
    index: &impl RawStorageImages<(ProofStatus, ProofId), ()>,
    max_work: u64,
) -> Result<(), GroupedOwnershipError> {
    validate(rows, index, &mut Work(max_work))
}

/// Stream the exact ordered membership rows without rebuilding either image.
fn index_members<'a>(
    index: &'a impl RawStorageImages<(ProofStatus, ProofId), ()>,
    image: GroupImage,
) -> impl FnMut(&mut Work) -> Result<Option<&'a (ProofStatus, ProofId)>, GroupedOwnershipError> {
    let mut current = index.current_entries();
    let mut undo = index.undo_entries();
    let mut current_row = None;
    let mut undo_row = None;
    let mut advance_current = true;
    let mut advance_undo = image == GroupImage::Predecessor;
    move |work| loop {
        if advance_current {
            current_row = next_physical(&mut current, work)?;
            advance_current = false;
        }
        if advance_undo {
            undo_row = next_physical(&mut undo, work)?;
            advance_undo = false;
        }
        match (current_row, undo_row) {
            (Some((current_key, ())), Some((undo_key, prior))) => {
                work.charge()?;
                let member_order = compare_keys(&current_key.1, &undo_key.1, work)?;
                match current_key.0.cmp(&undo_key.0).then(member_order) {
                    Ordering::Less => {
                        advance_current = true;
                        return Ok(Some(current_key));
                    }
                    Ordering::Equal => {
                        advance_current = true;
                        advance_undo = true;
                        if prior.is_some() {
                            return Ok(Some(undo_key));
                        }
                    }
                    Ordering::Greater => {
                        advance_undo = true;
                        if prior.is_some() {
                            return Ok(Some(undo_key));
                        }
                    }
                }
            }
            (Some((key, ())), None) => {
                advance_current = true;
                return Ok(Some(key));
            }
            (None, Some((key, prior))) => {
                advance_undo = true;
                if prior.is_some() {
                    return Ok(Some(key));
                }
            }
            (None, None) => return Ok(None),
        }
    }
}

fn validate(
    rows: &impl RawStorageImages<ProofId, ProofRecord>,
    index: &impl RawStorageImages<(ProofStatus, ProofId), ()>,
    work: &mut Work,
) -> Result<(), GroupedOwnershipError> {
    for image in [GroupImage::Current, GroupImage::Predecessor] {
        let corrupt = |mismatch| GroupedOwnershipError::Corrupt {
            index: INDEX,
            image,
            mismatch,
        };
        let mut next_member = index_members(index, image);
        let mut member = next_member(work)?;
        for status in STATUSES {
            work.charge()?;
            // Filtering preserves source-key order. Exact sequence equality
            // proves both directions without variable-key tree searches.
            visit_proofs(rows, image, work, |key, record, work| {
                if record.status != status {
                    return Ok(());
                }
                let Some((member_status, member_key)) = member else {
                    return Err(corrupt(GroupMismatch::MissingMember));
                };
                work.charge()?;
                if *member_status != status {
                    return Err(corrupt(GroupMismatch::MissingMember));
                }
                match compare_keys(key, member_key, work)? {
                    Ordering::Equal => {
                        member = next_member(work)?;
                        Ok(())
                    }
                    Ordering::Less => Err(corrupt(GroupMismatch::MissingMember)),
                    Ordering::Greater => Err(corrupt(GroupMismatch::ForeignMember)),
                }
            })?;
            if member.is_some_and(|(member_status, _)| *member_status == status) {
                return Err(corrupt(GroupMismatch::ForeignMember));
            }
        }
    }
    Ok(())
}

/// Pay the complete maximum byte comparison before inspecting either backend.
fn compare_keys(
    left: &ProofId,
    right: &ProofId,
    work: &mut Work,
) -> Result<Ordering, GroupedOwnershipError> {
    let demand = left
        .backend
        .len()
        .checked_add(right.backend.len())
        .and_then(|bytes| bytes.checked_add(2 * size_of::<[u8; 32]>()))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(GroupedOwnershipError::WorkLimit)?;
    work.0 = work
        .0
        .checked_sub(demand)
        .ok_or(GroupedOwnershipError::WorkLimit)?;
    Ok(left.cmp(right))
}

fn next_physical<'a, K: 'a, V: 'a>(
    rows: &mut impl Iterator<Item = (&'a K, &'a V)>,
    work: &mut Work,
) -> Result<Option<(&'a K, &'a V)>, GroupedOwnershipError> {
    let row = rows.next();
    if row.is_some() {
        // Charge before inspecting/filtering a physical row, even a tombstone.
        work.charge()?;
    }
    Ok(row)
}

/// Merge the original maps in key order, with prepaid variable-key comparisons.
fn visit_proofs(
    rows: &impl RawStorageImages<ProofId, ProofRecord>,
    image: GroupImage,
    work: &mut Work,
    mut visit: impl FnMut(&ProofId, &ProofRecord, &mut Work) -> Result<(), GroupedOwnershipError>,
) -> Result<(), GroupedOwnershipError> {
    let mut current = rows.current_entries();
    if image == GroupImage::Current {
        while let Some((key, value)) = next_physical(&mut current, work)? {
            visit(key, value, work)?;
        }
        return Ok(());
    }
    let mut undo = rows.undo_entries();
    let mut current_row = next_physical(&mut current, work)?;
    let mut undo_row = next_physical(&mut undo, work)?;
    loop {
        match (current_row, undo_row) {
            (Some((current_key, current_value)), Some((undo_key, prior))) => {
                match compare_keys(current_key, undo_key, work)? {
                    Ordering::Less => {
                        visit(current_key, current_value, work)?;
                        current_row = next_physical(&mut current, work)?;
                    }
                    Ordering::Equal => {
                        if let Some(value) = prior {
                            visit(undo_key, value, work)?;
                        }
                        current_row = next_physical(&mut current, work)?;
                        undo_row = next_physical(&mut undo, work)?;
                    }
                    Ordering::Greater => {
                        if let Some(value) = prior {
                            visit(undo_key, value, work)?;
                        }
                        undo_row = next_physical(&mut undo, work)?;
                    }
                }
            }
            (Some((key, value)), None) => {
                visit(key, value, work)?;
                current_row = next_physical(&mut current, work)?;
            }
            (None, Some((key, prior))) => {
                if let Some(value) = prior {
                    visit(key, value, work)?;
                }
                undo_row = next_physical(&mut undo, work)?;
            }
            (None, None) => return Ok(()),
        }
    }
}

#[cfg(test)]
mod tests;
