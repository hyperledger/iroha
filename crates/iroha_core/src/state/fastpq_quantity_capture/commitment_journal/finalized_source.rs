//! Mandatory original completed source and charged D7 material before result authentication.
//!
//! The sole caller owns the actual completed execution-source capsule. This local
//! owner supplies the mandatory ordinary-witness commitment; it grants no finality.

use super::*;
mod witness;
use crate::execution_attempt::ExecutionAttemptError;
use iroha_allocation::{AllocationBudget, ChargedShared, PrepaidBufferError, PrepaidSharedError};
use iroha_data_model::fastpq::{
    FastpqOrdinarySourceStatementLeafV1, FastpqOrdinarySourceStatementManifestV1,
    FastpqSourceEffectCoverageV1, build_fastpq_ordinary_source_statement_manifest_v1,
};
use std::{alloc::Layout, io, sync::Arc};
pub(crate) use witness::{AdmittedQuantityArchive, CapturedExecWitness, CapturedQuantityEntry};

type SourceResult<T> = Result<T, ExecutionAttemptError<String>>;
fn owner(message: &str) -> ExecutionAttemptError<String> {
    ExecutionAttemptError::Rejected(message.to_owned())
}
fn overflow() -> ExecutionAttemptError<String> {
    ExecutionAttemptError::Deferred(AllocationRefusal::DemandOverflow.into())
}
fn buffer(error: PrepaidBufferError) -> ExecutionAttemptError<String> {
    match error {
        PrepaidBufferError::Allocation(ChargedBufferError::Admission(refusal)) => {
            ExecutionAttemptError::Deferred(refusal.into())
        }
        PrepaidBufferError::Allocation(ChargedBufferError::Allocator { .. }) => {
            ExecutionAttemptError::Deferred(
                ivm::error::ExecutionDeferral::AllocationUnavailable.into(),
            )
        }
        PrepaidBufferError::Reservation(_) => {
            owner("mandatory source lost its exact prepaid backing")
        }
    }
}

/// Immutable original complete source, retaining every new allocation's original charge.
/// Sharing this owner never clones the tape, leaf backing or encoded manifest.
pub(super) struct FinalizedQuantitySource {
    inventory: Arc<FastpqSourceInventoryV1>,
    frozen: Arc<crate::fastpq::FastpqBlockStartSourceContext>,
    creation_time_ms: u64,
    applied_world_transactions: u64,
    balance_observation: (bool, u64),
    supply_observation: (bool, u64),
    leaves: ChargedBuffer<FastpqOrdinarySourceStatementLeafV1>,
    manifest: FastpqOrdinarySourceStatementManifestV1,
    manifest_bytes: ChargedBuffer<u8>,
    permission_root: [u8; 32],
    permission_seal: crate::fastpq::permission_context::PermissionContextSeal,
    /// The original finite execution pool; sharing this handle creates no capacity.
    pool: AllocationBudget,
}

struct FixedWriter<'a>(&'a mut ChargedBuffer<u8>);
impl io::Write for FixedWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.0.capacity() - self.0.as_slice().len() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        for byte in bytes {
            self.0.push_reserved(*byte);
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl FinalizedQuantitySource {
    fn prepare(block: &StateBlock<'_>) -> SourceResult<ChargedShared<Self>> {
        let journal = &block.fastpq_quantity_candidate.commitments;
        if journal.invalid || journal.sealed.is_some() {
            return Err(owner(
                "mandatory quantity source lost its original open journal",
            ));
        }
        let inventory = block
            .verified_fastpq_source_inventory_for_capture()
            .map_err(ExecutionAttemptError::Rejected)?;
        let frozen = block
            .fastpq_source_context
            .as_ref()
            .ok_or_else(|| owner("mandatory source has no original block-start custody"))?;
        // Mandatory consensus projection is bounded by the canonical source's u32
        // representability. Optional proof-profile limits cannot change these bytes.
        let source_count = u32::try_from(inventory.entries().len()).map_err(|_| overflow())?;
        let mut present = 0usize;
        let mut count = 0usize;
        for entry in inventory.entries() {
            if let Some(commitment) = journal.get(&entry.entry_hash) {
                present = present.checked_add(1).ok_or_else(overflow)?;
                if commitment.context()
                    != &(FastpqExecutionEffectContextV1 {
                        source: inventory.source(),
                        entry: *entry,
                    })
                {
                    return Err(owner(
                        "original quantity context differs from its complete executed entry",
                    ));
                }
                if commitment.count() != 0 {
                    count = count.checked_add(1).ok_or_else(overflow)?;
                }
            }
        }
        if present != journal.entry_count() {
            return Err(owner(
                "complete executed census omitted an original quantity source",
            ));
        }
        let leaf_layout =
            Layout::array::<FastpqOrdinarySourceStatementLeafV1>(count).map_err(|_| overflow())?;
        let role_layout = crate::fastpq::permission_context::permission_table_backing_layout(
            block.world.roles.iter(),
        )
        .map_err(|_| overflow())?;
        let value_capacity =
            iroha_data_model::fastpq::FASTPQ_SOURCE_STATEMENT_MANIFEST_MAX_BYTES_V1;
        let value_layout = Layout::array::<u8>(value_capacity).map_err(|_| overflow())?;
        let shared_layout = ChargedShared::<Self>::allocation_layout();
        let demand = leaf_layout
            .size()
            .checked_add(role_layout.size())
            .and_then(|v| v.checked_add(value_layout.size()))
            .and_then(|v| v.checked_add(shared_layout.size()))
            .ok_or_else(overflow)?;
        let pool = block.pipeline_ivm_prepared_cache.execution_budget();
        let mut reservation = pool
            .try_reserve_bytes(demand)
            .map_err(|refusal| ExecutionAttemptError::Deferred(refusal.into()))?;
        let shared =
            ChargedShared::reserve_from(&mut reservation).map_err(|error| match error {
                PrepaidSharedError::Reservation(_) => {
                    owner("mandatory source lost its exact shared-shell reservation")
                }
                PrepaidSharedError::Allocator { .. } => ExecutionAttemptError::Deferred(
                    ivm::error::ExecutionDeferral::AllocationUnavailable.into(),
                ),
            })?;
        let mut leaves =
            ChargedBuffer::from_reservation(count, &mut reservation).map_err(buffer)?;
        let mut manifest_bytes =
            ChargedBuffer::from_reservation(value_capacity, &mut reservation).map_err(buffer)?;
        let permission_seal = crate::fastpq::permission_context::prepaid_permission_table_seal(
            || block.world.roles.iter(),
            &mut reservation,
        )
        .map_err(|error| match error {
            crate::fastpq::permission_context::PermissionContextError::Capacity => {
                ExecutionAttemptError::Deferred(
                    ivm::error::ExecutionDeferral::AllocationUnavailable.into(),
                )
            }
            crate::fastpq::permission_context::PermissionContextError::Encoding => {
                owner("mandatory permission context failed canonical encoding")
            }
        })?;
        let permission_root = permission_seal.root();
        if reservation.remaining_bytes() != 0 {
            return Err(owner("mandatory source left unaccounted prepaid backing"));
        }
        let creation_time_ms = block._curr_block.creation_time_ms;
        let slot = creation_time_ms.saturating_mul(1_000_000);
        for (entry_index, entry) in inventory.entries().iter().enumerate() {
            let Some(commitment) = journal
                .get(&entry.entry_hash)
                .filter(|value| value.count() != 0)
            else {
                continue;
            };
            leaves.push_reserved(FastpqOrdinarySourceStatementLeafV1 {
                source: inventory.source(),
                statement_index: u32::try_from(leaves.as_slice().len()).map_err(|_| overflow())?,
                entry_index: u32::try_from(entry_index).map_err(|_| overflow())?,
                effect_count: commitment.count(),
                entry_hash: entry.entry_hash,
                execution_kind: entry.execution_kind,
                route: entry.route,
                dataspace_id: entry.dataspace_id,
                effects_digest: commitment
                    .digest()
                    .map_err(|_| {
                        owner("mandatory ordered quantity source digest failed canonical encoding")
                    })?
                    .into(),
                slot,
                perm_root: permission_root,
                tx_set_hash: inventory.tx_set_hash(),
            });
        }
        let mut manifest = build_fastpq_ordinary_source_statement_manifest_v1(
            inventory.source(),
            inventory.entries(),
            leaves.as_slice(),
            source_count,
            source_count,
        )
        .ok_or_else(|| {
            owner("mandatory quantity source manifest differs from the complete original census")
        })?;
        manifest.coverage = if journal.unsupported.is_some() {
            FastpqSourceEffectCoverageV1::Unsupported
        } else {
            FastpqSourceEffectCoverageV1::Complete
        };
        norito::core::write_canonical_to_writer(&manifest, &mut FixedWriter(&mut manifest_bytes))
            .map_err(|_| owner("mandatory source manifest failed exact bounded canonical encoding"))?;
        Ok(shared.initialize(Self {
            inventory,
            frozen: Arc::clone(frozen),
            creation_time_ms,
            applied_world_transactions: block.fastpq_quantity_candidate.applied_world_transactions,
            balance_observation: block.world.assets.write_observation(),
            supply_observation: block.world.asset_definitions.write_observation(),
            leaves,
            manifest,
            manifest_bytes,
            permission_root,
            permission_seal,
            pool: pool.clone(),
        }))
    }

    fn verify_current(&self, block: &StateBlock<'_>) -> Result<(), String> {
        let current = block.verified_fastpq_source_inventory_for_capture()?;
        let journal = &block.fastpq_quantity_candidate.commitments;
        let pool = block.pipeline_ivm_prepared_cache.execution_budget();
        if !Arc::ptr_eq(&self.inventory, &current)
            || block
                .fastpq_source_context
                .as_ref()
                .is_none_or(|current| !Arc::ptr_eq(&self.frozen, current))
            || self.creation_time_ms != block._curr_block.creation_time_ms
            || self.applied_world_transactions
                != block.fastpq_quantity_candidate.applied_world_transactions
            || self.balance_observation != block.world.assets.write_observation()
            || self.supply_observation != block.world.asset_definitions.write_observation()
            || journal.invalid
            || journal.sealed.as_ref().is_none_or(|retained| {
                !std::ptr::eq(self, &raw const **retained)
                    || !retained.belongs_to(pool)
                    || !retained.belongs_to(&self.pool)
            })
            || !self.leaves.belongs_to(&self.pool)
            || !self.manifest_bytes.belongs_to(&self.pool)
            || !self.leaves.belongs_to(pool)
            || !self.manifest_bytes.belongs_to(pool)
            || self.manifest.coverage
                != if journal.unsupported.is_some() {
                    FastpqSourceEffectCoverageV1::Unsupported
                } else {
                    FastpqSourceEffectCoverageV1::Complete
                }
        {
            return Err(
                "mandatory finalized quantity source lost original custody or context".into(),
            );
        }
        if !self
            .permission_seal
            .matches(block.world.roles.iter())
            .map_err(|_| "mandatory source permission context encoding changed".to_owned())?
        {
            return Err("mandatory finalized permission table changed".into());
        }
        let mut present = 0usize;
        let mut statement_index = 0usize;
        for (entry_index, entry) in self.inventory.entries().iter().enumerate() {
            let Some(original) = journal.get(&entry.entry_hash) else {
                continue;
            };
            present = present
                .checked_add(1)
                .ok_or("retained source count changed")?;
            if original.context()
                != &(FastpqExecutionEffectContextV1 {
                    source: self.inventory.source(),
                    entry: *entry,
                })
            {
                return Err("mandatory finalized source context changed".into());
            }
            if original.count() == 0 {
                continue;
            }
            let expected = FastpqOrdinarySourceStatementLeafV1 {
                source: self.inventory.source(),
                statement_index: u32::try_from(statement_index)
                    .map_err(|_| "retained source index changed")?,
                entry_index: u32::try_from(entry_index)
                    .map_err(|_| "retained source index changed")?,
                effect_count: original.count(),
                entry_hash: entry.entry_hash,
                execution_kind: entry.execution_kind,
                route: entry.route,
                dataspace_id: entry.dataspace_id,
                effects_digest: original
                    .digest()
                    .map_err(|_| "mandatory source digest encoding changed".to_owned())?
                    .into(),
                slot: self.creation_time_ms.saturating_mul(1_000_000),
                perm_root: self.permission_root,
                tx_set_hash: self.inventory.tx_set_hash(),
            };
            if self.leaves.as_slice().get(statement_index) != Some(&expected) {
                return Err("mandatory finalized original effect commitment changed".into());
            }
            statement_index = statement_index
                .checked_add(1)
                .ok_or("retained source count changed")?;
        }
        if present != journal.entry_count() || statement_index != self.leaves.as_slice().len() {
            return Err("mandatory finalized source census changed".into());
        }
        Ok(())
    }
}

impl StateBlock<'_> {
    /// Sole completed-source producer join, before optional archive capture or result sealing.
    pub(in crate::state) fn retain_finalized_quantity_source(&mut self) -> SourceResult<()> {
        self.observe_quantity_block_journals();
        let prepared = FinalizedQuantitySource::prepare(self)?;
        self.fastpq_quantity_candidate.commitments.sealed = Some(prepared);
        Ok(())
    }

    /// Test-only read of genuine completed source leaves; no raw source constructor.
    #[cfg(test)]
    pub(in crate::state) fn finalized_quantity_source_for_test(
        &self,
    ) -> SourceResult<(
        FastpqOrdinarySourceStatementManifestV1,
        &[FastpqOrdinarySourceStatementLeafV1],
        &[u8],
    )> {
        let retained = self
            .fastpq_quantity_candidate
            .commitments
            .sealed
            .as_ref()
            .ok_or_else(|| owner("original completed quantity source missing"))?;
        retained.verify_current(self)?;
        Ok((
            retained.manifest,
            retained.leaves.as_slice(),
            retained.manifest_bytes.as_slice(),
        ))
    }
}
