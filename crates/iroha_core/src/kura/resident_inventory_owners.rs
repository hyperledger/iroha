use resident_inventory::ResidentOwner;

impl ResidentOwner for BlockData {
    const FAMILY: resource_inventory::Family = resource_inventory::Family::ResidentCanonical;

    fn resident_associations(&self) -> std::result::Result<u64, resource_inventory::Unavailable> {
        // A deferred logical height is not the number of materialized hash slots.
        resident_inventory::lengths([match self {
            Self::Dense(entries) => entries.len(),
            Self::Deferred { entries, .. } => entries.len(),
        }])
    }

    fn resident_complete(&self) -> bool {
        matches!(self, Self::Dense(_))
    }
}

impl ResidentOwner for BlockHeightIndex {
    const FAMILY: resource_inventory::Family = resource_inventory::Family::ResidentCanonical;

    fn resident_associations(&self) -> std::result::Result<u64, resource_inventory::Unavailable> {
        resident_inventory::lengths([self.len()])
    }

    fn resident_complete(&self) -> bool {
        true
    }
}

impl ResidentOwner for TransactionEntrypointIndex {
    const FAMILY: resource_inventory::Family = resource_inventory::Family::ResidentTransaction;

    fn resident_associations(&self) -> std::result::Result<u64, resource_inventory::Unavailable> {
        let markers = resident_inventory::lengths([
            self.indexed_heights.len(),
            self.incomplete_heights.len(),
            self.inventories_by_height.len(),
        ])?;
        self.nested_associations
            .get()?
            .checked_add(markers)
            .ok_or(resource_inventory::Unavailable::Arithmetic)
    }

    fn resident_complete(&self) -> bool {
        self.complete && self.incomplete_heights.is_empty()
    }
}

impl Kura {
    /// Register only fully reconstructed resident owners, without doing reconstruction.
    ///
    /// Reads existing owner locks independently in their usual direction. The shared
    /// generation rejects a mutation crossing these fixed-size observations. This is
    /// an explicit preparation/reconciliation operation, never the telemetry scrape.
    /// Other physical resource families remain unregistered until their own exact audits finish.
    pub(crate) fn reconcile_resident_resource_inventory(
        &self,
    ) -> std::result::Result<(), resource_inventory::Unavailable> {
        fn exact(owner: &impl ResidentOwner) -> std::result::Result<u64, Unavailable> {
            if !owner.resident_complete() {
                return Err(Unavailable::InvalidInventory);
            }
            owner.resident_associations()
        }

        use resource_inventory::{Family, Unavailable, Usage};
        let generation = self.resource_inventory.reconciliation_generation()?;
        if self.auxiliary_history_deferred {
            return Err(Unavailable::InvalidInventory);
        }
        let materialized_hashes = {
            let owner = self.block_data.lock();
            exact(&owner)?
        };
        let reverse_hashes = {
            let owner = self.block_height_index.lock();
            exact(&owner)?
        };
        let canonical = materialized_hashes
            .checked_add(reverse_hashes)
            .ok_or(Unavailable::Arithmetic)?;
        let transactions = exact(&self.transaction_entrypoint_index.lock())?;
        let lane_entries = exact(&self.lane_storage_entries.lock())?;
        let frontier = lane_entries;
        let pipeline = exact(&self.pipeline_sidecar_queue.lock())?;
        let proofs = exact(&self.fastpq_proof_queue.lock())?;
        let queues = pipeline
            .checked_add(proofs)
            .ok_or(Unavailable::Arithmetic)?;
        let usage = |resident_associations| Usage {
            resident_associations,
            ..Usage::default()
        };
        self.resource_inventory.initialize(
            generation,
            &[
                (Family::ResidentCanonical, usage(canonical)),
                (Family::ResidentTransaction, usage(transactions)),
                (Family::ResidentFrontier, usage(frontier)),
                (Family::ResidentQueue, usage(queues)),
            ],
        )
    }
}

// Each association below is a stored metadata lookup/queue record. Payload
// internals and allocator capacities remain the separate process RSS measure.

macro_rules! flat_resident_owner {
    ($owner:ty, $family:ident) => {
        impl resident_inventory::ResidentOwner for $owner {
            const FAMILY: resource_inventory::Family = resource_inventory::Family::$family;
            fn resident_associations(
                &self,
            ) -> std::result::Result<u64, resource_inventory::Unavailable> {
                resident_inventory::lengths([self.len()])
            }
            fn resident_complete(&self) -> bool {
                true
            }
        }
    };
}
flat_resident_owner!(VecDeque<PipelineRecoverySidecar>, ResidentQueue);
flat_resident_owner!(VecDeque<QueuedFastpqProofSnapshot>, ResidentQueue);
flat_resident_owner!(BTreeMap<LaneId,LaneStorageEntry>, ResidentFrontier);
