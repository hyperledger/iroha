//! Original completed source census joined to immutable candidate quantity tapes.
//!
//! Every producer invocation remains explicit, including rejected and zero-effect
//! calls. This local owner grants no finality, proof availability or publication.
//! TODO: close lifecycle, mandatory supply and full physical source ownership, then
//! integrate the complete relation and atomic D7/finalized custody before export.

use super::*;
use crate::state::fastpq_quantity_archive::FrozenQuantityArchive;
use iroha_allocation::{AllocationBudget, ChargedShared, ReservedChargedShared};
use iroha_data_model::fastpq::FastpqSourceStatementContextV1;
use std::sync::Arc;

/// A failed or interrupted original attempt cannot be replaced with another census.
#[derive(Default)]
pub(super) enum QuantitySourceCensusState {
    #[default]
    Unsealed,
    Preparing,
    Sealed(QuantitySourceCensus),
    Failed,
}

impl QuantitySourceCensusState {
    pub(super) fn is_preparing_or_sealed(&self) -> bool {
        matches!(self, Self::Preparing | Self::Sealed(_))
    }
}

/// Fixed-size facts for one position in the original producer's complete order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct QuantitySourceEntrySeal {
    pub(super) context: FastpqExecutionEffectContextV1,
    pub(super) effect_count: u32,
    pub(super) frame_bytes: u64,
    pub(super) effects_digest: Hash,
}

/// Move-only retention of the exact original inventory and its quantity projection.
///
/// The new fixed backing is charged before allocation. The inventory and frozen
/// source contexts retain their existing Arc allocations without cloning contents.
/// Original inventory allocation and canonical serializer scratch remain their
/// existing owners' obligations; this does not claim complete physical capture.
pub(super) struct QuantitySourceCensus {
    entries: ChargedBuffer<QuantitySourceEntrySeal>,
    inventory: Arc<FastpqSourceInventoryV1>,
    frozen: Arc<crate::fastpq::FastpqBlockStartSourceContext>,
    creation_time_ms: u64,
    /// Final execution role/permission/epoch table, not account-role authority.
    permission: crate::fastpq::permission_context::PermissionContextSeal,
    applied_world_transactions: u64,
    usage: QuantityCandidateUsage,
    /// Reserved before any capture backing, then consumed by the original finalizer.
    pending_archive: Option<ReservedChargedShared<FrozenQuantityArchive<QuantityArchivedEntry>>>,
    /// The exact original immutable tape-map allocation and all nested credits.
    archive: Option<ChargedShared<FrozenQuantityArchive<QuantityArchivedEntry>>>,
    /// Same finite execution pool; cloning this handle creates no capacity.
    pool: AllocationBudget,
}

fn entry_seal(
    archive: &QuantityCandidateArchive,
    source: FastpqSourceStatementContextV1,
    entry: FastpqSourceExecutionEntryV1,
) -> Result<(QuantitySourceEntrySeal, QuantityCandidateUsage), QuantityCaptureIssue> {
    let context = FastpqExecutionEffectContextV1 { source, entry };
    let empty = FastpqExecutionEffectsV1 {
        context,
        effects: Vec::new(),
    };
    let captured = archive.entries.get(&entry.entry_hash);
    let wire = captured.map_or(&empty, |captured| &**captured);
    let effect_count =
        u32::try_from(wire.effects.len()).map_err(|_| QuantityCaptureIssue::Capacity)?;
    let frame_bytes = u64::try_from(
        norito::canonical_frame_len(wire).map_err(|_| QuantityCaptureIssue::InvalidFacts)?,
    )
    .map_err(|_| QuantityCaptureIssue::Capacity)?;
    let usage = if let Some(captured) = captured {
        if captured.context != context
            || wire.context != context
            || effect_count == 0
            || captured.measurement.baseline != QuantityCandidateUsage::default()
            || captured.measurement.full.entries != 1
            || captured.measurement.full.deltas != u64::from(effect_count)
            || captured.measurement.full.statement_bytes != frame_bytes
            || wire
                .effects
                .iter()
                .enumerate()
                .any(|(index, effect)| usize::try_from(effect.ordinal).ok() != Some(index))
        {
            return Err(QuantityCaptureIssue::InvalidFacts);
        }
        captured.measurement.full
    } else {
        QuantityCandidateUsage::default()
    };
    // This is the exact complete-effect prover domain, not an untyped frame hash.
    // Context, effect ordinals and every original quantity/authority fact are bound.
    let effects_digest = iroha_data_model::fastpq::execution_effects_digest_v1(wire)
        .map_err(|_| QuantityCaptureIssue::InvalidFacts)?;
    let original = archive.commitments.original(context)?;
    if original.count() != effect_count
        || original
            .digest()
            .map_err(|_| QuantityCaptureIssue::InvalidFacts)?
            != effects_digest
    {
        return Err(QuantityCaptureIssue::InvalidFacts);
    }
    Ok((
        QuantitySourceEntrySeal {
            context,
            effect_count,
            frame_bytes,
            effects_digest,
        },
        usage,
    ))
}

impl QuantitySourceCensus {
    pub(super) fn prepare(
        block: &StateBlock<'_>,
        budget: &AllocationBudget,
    ) -> Result<Self, QuantityCaptureIssue> {
        let archive = &block.fastpq_quantity_candidate;
        if let Some(issue) = archive.issue {
            return Err(issue);
        }
        let inventory = block
            .verified_fastpq_source_inventory_for_capture()
            .map_err(|_| QuantityCaptureIssue::UnsupportedOwner)?;
        let frozen = block
            .fastpq_source_context
            .as_ref()
            .ok_or(QuantityCaptureIssue::UnsupportedOwner)?;
        let limits = block.fastpq_source_policy_at_block_start().0.block;
        if u64::try_from(inventory.entries().len()).map_err(|_| QuantityCaptureIssue::Capacity)?
            > u64::from(limits.max_executed_entries)
            || archive.usage.entries > u64::from(limits.max_executed_entries)
            || archive.usage.deltas > u64::from(limits.max_deltas)
            || archive.usage.input_bytes > limits.max_input_transcript_bytes
            || archive.usage.statement_bytes > limits.max_total_statement_bytes
        {
            return Err(QuantityCaptureIssue::Capacity);
        }
        let entry_layout =
            std::alloc::Layout::array::<QuantitySourceEntrySeal>(inventory.entries().len())
                .map_err(|_| QuantityCaptureIssue::Capacity)?;
        let permission_layout = crate::fastpq::permission_context::permission_table_backing_layout(
            block.world.roles.iter(),
        )
        .map_err(|_| QuantityCaptureIssue::Capacity)?;
        let archive_layout =
            ChargedShared::<FrozenQuantityArchive<QuantityArchivedEntry>>::allocation_layout();
        let required = entry_layout
            .size()
            .checked_add(permission_layout.size())
            .and_then(|bytes| bytes.checked_add(archive_layout.size()))
            .ok_or(QuantityCaptureIssue::Capacity)?;
        // One original admission funds both complete explicit backings before
        // allocating either. The role scratch is freed after its digest is made.
        let mut reservation = budget
            .try_reserve_bytes(required)
            .map_err(|_| QuantityCaptureIssue::Capacity)?;
        let mut entries =
            ChargedBuffer::from_reservation(inventory.entries().len(), &mut reservation)
                .map_err(|_| QuantityCaptureIssue::Capacity)?;
        let pending_archive = ChargedShared::reserve_from(&mut reservation)
            .map_err(|_| QuantityCaptureIssue::Capacity)?;
        let mut usage = QuantityCandidateUsage::default();
        for entry in inventory.entries() {
            let (seal, contribution) = entry_seal(archive, inventory.source(), *entry)?;
            usage = usage
                .checked_add(contribution)
                .ok_or(QuantityCaptureIssue::Capacity)?;
            entries.push_reserved(seal);
        }
        if usage != archive.usage
            || inventory
                .entries()
                .iter()
                .filter(|entry| archive.commitments.get(&entry.entry_hash).is_some())
                .count()
                != archive.commitments.entry_count()
            || usize::try_from(usage.entries).ok() != Some(archive.entries.len())
        {
            return Err(QuantityCaptureIssue::InvalidFacts);
        }
        let permission = crate::fastpq::permission_context::prepaid_permission_table_seal(
            || block.world.roles.iter(),
            &mut reservation,
        )
        .map_err(|error| match error {
            crate::fastpq::permission_context::PermissionContextError::Capacity => {
                QuantityCaptureIssue::Capacity
            }
            crate::fastpq::permission_context::PermissionContextError::Encoding => {
                QuantityCaptureIssue::InvalidFacts
            }
        })?;
        if reservation.remaining_bytes() != 0 {
            return Err(QuantityCaptureIssue::InvalidFacts);
        }
        Ok(Self {
            entries,
            inventory,
            frozen: Arc::clone(frozen),
            creation_time_ms: block._curr_block.creation_time_ms,
            permission,
            applied_world_transactions: archive.applied_world_transactions,
            usage,
            pending_archive: Some(pending_archive),
            archive: None,
            pool: budget.clone(),
        })
    }

    /// Consume the original tape-map backing into its prepaid immutable shell.
    /// Called only within the same completed producer finalizer after preparation.
    fn retain_original_archive(
        &mut self,
        archive: &mut QuantityCandidateArchive,
    ) -> Result<(), QuantityCaptureIssue> {
        let incoming_issue = &archive.issue;
        if incoming_issue.is_some()
            || self.archive.is_some()
            || archive.applied_world_transactions != self.applied_world_transactions
            || archive.usage != self.usage
            || !archive.entries.belongs_to(&self.pool)
            || archive
                .entries
                .iter()
                .any(|(_, entry)| !entry.tape.belongs_to(&self.pool))
        {
            return Err(QuantityCaptureIssue::InvalidFacts);
        }
        let shell = self
            .pending_archive
            .take()
            .ok_or(QuantityCaptureIssue::InvalidFacts)?;
        self.archive = Some(archive.entries.freeze(shell)?);
        Ok(())
    }

    fn verify_current(&self, block: &StateBlock<'_>) -> Result<(), QuantityCaptureIssue> {
        let archive = &block.fastpq_quantity_candidate;
        let current = block
            .verified_fastpq_source_inventory_for_capture()
            .map_err(|_| QuantityCaptureIssue::UnsupportedOwner)?;
        if !Arc::ptr_eq(&self.inventory, &current)
            || self.pending_archive.is_some()
            || self
                .archive
                .as_ref()
                .is_none_or(|retained| !archive.entries.retains_frozen(retained))
            || !archive.entries.belongs_to(&self.pool)
            || block
                .fastpq_source_context
                .as_ref()
                .is_none_or(|frozen| !Arc::ptr_eq(&self.frozen, frozen))
            || self.creation_time_ms != block._curr_block.creation_time_ms
            || self.applied_world_transactions != archive.applied_world_transactions
            || self.usage != archive.usage
            || self.entries.as_slice().len() != self.inventory.entries().len()
        {
            return Err(QuantityCaptureIssue::InvalidFacts);
        }
        if !self
            .permission
            .matches(block.world.roles.iter())
            .map_err(|_| QuantityCaptureIssue::InvalidFacts)?
        {
            return Err(QuantityCaptureIssue::InvalidFacts);
        }
        let mut usage = QuantityCandidateUsage::default();
        for (retained, original) in self.entries.as_slice().iter().zip(self.inventory.entries()) {
            let (current, contribution) = entry_seal(archive, self.inventory.source(), *original)?;
            if retained != &current {
                return Err(QuantityCaptureIssue::InvalidFacts);
            }
            usage = usage
                .checked_add(contribution)
                .ok_or(QuantityCaptureIssue::Capacity)?;
        }
        if usage != self.usage
            || self
                .inventory
                .entries()
                .iter()
                .filter(|entry| archive.commitments.get(&entry.entry_hash).is_some())
                .count()
                != archive.commitments.entry_count()
            || usize::try_from(usage.entries).ok() != Some(archive.entries.len())
        {
            return Err(QuantityCaptureIssue::InvalidFacts);
        }
        Ok(())
    }

    /// Retain only the actual sealed optional archive for later original-pool work.
    pub(super) fn retained_archive_for_work(
        &self,
        block: &StateBlock<'_>,
    ) -> Result<ChargedShared<FrozenQuantityArchive<QuantityArchivedEntry>>, QuantityCaptureIssue>
    {
        self.verify_current(block)?;
        self.archive
            .clone()
            .ok_or(QuantityCaptureIssue::InvalidFacts)
    }

    #[cfg(test)]
    pub(super) fn entries(&self) -> &[QuantitySourceEntrySeal] {
        self.entries.as_slice()
    }

    #[cfg(test)]
    pub(super) fn retained_archive(
        &self,
    ) -> ChargedShared<FrozenQuantityArchive<QuantityArchivedEntry>> {
        self.archive
            .as_ref()
            .expect("original completed source archive")
            .clone()
    }

    #[cfg(test)]
    pub(super) fn statement_context(
        &self,
        entry_index: usize,
    ) -> Option<iroha_data_model::fastpq::FastpqPublicInputs> {
        let entry = self.entries.as_slice().get(entry_index)?;
        Some(iroha_data_model::fastpq::FastpqPublicInputs {
            dsid: crate::fastpq::dataspace_id_bytes(entry.context.entry.dataspace_id),
            slot: self.creation_time_ms.saturating_mul(1_000_000),
            old_root: [0; 32],
            new_root: [0; 32],
            perm_root: self.permission.root(),
            tx_set_hash: self.inventory.tx_set_hash(),
        })
    }
}

impl StateBlock<'_> {
    /// Called solely by the original completed output producer's successful finalizer.
    pub(in crate::state) fn retain_quantity_source_census(&mut self) {
        self.observe_quantity_block_journals();
        if self.fastpq_quantity_candidate.issue.is_some() {
            return;
        }
        if !matches!(
            self.fastpq_quantity_candidate.source_census,
            QuantitySourceCensusState::Unsealed
        ) {
            self.fastpq_quantity_candidate
                .poison(QuantityCaptureIssue::InvalidFacts);
            return;
        }
        // A caught unwind leaves Preparing; observation refuses it and cannot retry.
        self.fastpq_quantity_candidate.source_census = QuantitySourceCensusState::Preparing;
        let prepared = QuantitySourceCensus::prepare(
            self,
            self.pipeline_ivm_prepared_cache.execution_budget(),
        );
        match prepared {
            Ok(mut census) => {
                match census.retain_original_archive(&mut self.fastpq_quantity_candidate) {
                    Ok(()) => {
                        self.fastpq_quantity_candidate.source_census =
                            QuantitySourceCensusState::Sealed(census)
                    }
                    Err(issue) => self.fastpq_quantity_candidate.poison(issue),
                }
            }
            Err(issue) => self.fastpq_quantity_candidate.poison(issue),
        }
    }

    pub(in crate::state) fn reject_quantity_source_census(&mut self) {
        self.fastpq_quantity_candidate
            .poison(QuantityCaptureIssue::UnsupportedOwner);
    }

    pub(super) fn observe_quantity_source_census(&mut self) {
        let result = match &self.fastpq_quantity_candidate.source_census {
            QuantitySourceCensusState::Preparing => Err(QuantityCaptureIssue::InterruptedScope),
            QuantitySourceCensusState::Sealed(census) => census.verify_current(self),
            QuantitySourceCensusState::Unsealed | QuantitySourceCensusState::Failed => Ok(()),
        };
        if let Err(issue) = result {
            self.fastpq_quantity_candidate.poison(issue);
        }
    }
}
