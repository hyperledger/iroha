//! Resumable source-work admission over the same original dependency graph.
//!
//! Only successful original row/lookup substeps advance. A native read refusal
//! leaves the same scalar cursor and cumulative counters available for retry.
//! A configured work refusal is terminal for this exact policy: it cannot reset
//! already attempted geometry or acquire broader limits on a later call.

use super::*;

/// Scalar progress of original input admission, never semantic validity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::state) struct AdmissionProgress {
    pub shape_table: usize,
    pub shape_row: usize,
    pub shape_part: usize,
    pub evidence_row: usize,
    pub evidence_part: usize,
    pub provider: usize,
    pub provider_part: usize,
    pub geometry: SourceGeometryLimits,
    pub table_rows: u64,
    pub index_entries: u64,
    pub operations: u64,
    pub signatures: u64,
    pub complete: bool,
    pub stopped: Option<WorkRefusal>,
}

/// Existing admission plan and its exact unfinished original source substep.
pub(in crate::state) struct Admission {
    queries: [crate::state::deserialize::musubi_source_read::LookupCursor; 5],
    plan: Plan,
    passes: bool,
    shape_table: usize,
    shape_row: usize,
    shape_part: usize,
    evidence_row: usize,
    evidence_part: usize,
    provider: usize,
    provider_part: usize,
    complete: bool,
    stopped: Option<WorkRefusal>,
}
impl Admission {
    /// Bind finite local policy once. This creates no source or funding authority.
    pub(in crate::state) fn new(limits: SourceWorkLimits) -> Self {
        Self {
            plan: Plan::new(limits),
            queries: [crate::state::deserialize::musubi_source_read::LookupCursor::new(); 5],
            passes: false,
            shape_table: 0,
            shape_row: 0,
            shape_part: 0,
            evidence_row: 0,
            evidence_part: 0,
            provider: 0,
            provider_part: 0,
            complete: false,
            stopped: None,
        }
    }
    /// Observe retained counters without borrowing or resolving any source row.
    pub(in crate::state) fn progress(&self) -> AdmissionProgress {
        AdmissionProgress {
            shape_table: self.shape_table,
            shape_row: self.shape_row,
            shape_part: self.shape_part,
            evidence_row: self.evidence_row,
            evidence_part: self.evidence_part,
            provider: self.provider,
            provider_part: self.provider_part,
            geometry: self.plan.geometry.used(),
            table_rows: self.plan.table_rows,
            index_entries: self.plan.index_entries,
            operations: self.plan.operations,
            signatures: self.plan.signatures,
            complete: self.complete,
            stopped: self.stopped,
        }
    }
    /// Exact NFC peak after all original source shapes and work were admitted.
    pub(in crate::state) fn nfc_scratch_bytes(&self) -> Option<usize> {
        self.complete.then_some(self.plan.nfc_scratch_bytes)
    }
    pub(super) fn into_plan(self) -> Plan {
        self.plan
    }

    /// Continue this exact source. The enclosing native owner checks its identity.
    pub(in crate::state) fn advance<W: MusubiRead>(
        &mut self,
        world: &W,
    ) -> Result<AdmissionProgress, ReadFailure<W::Error, WorkRefusal>> {
        if let Some(original) = self.stopped {
            return Err(ReadFailure::Predicate(original));
        }
        let result = self.advance_inner(world);
        if let Err(ReadFailure::Predicate(original)) = &result {
            self.stopped = Some(*original);
        }
        result.map(|()| self.progress())
    }
    fn advance_inner<W: MusubiRead>(
        &mut self,
        world: &W,
    ) -> Result<(), ReadFailure<W::Error, WorkRefusal>> {
        if self.complete {
            return Ok(());
        }
        if !self.passes {
            // Counts are O(1) in the original closed frozen owner. Read every
            // fallible count into this scalar candidate before retaining it;
            // no actual row or expensive operation is executed by this prefix.
            let mut candidate = Plan::new(self.plan.limits);
            match admit_passes(world, &mut candidate) {
                Ok(()) => {
                    self.plan = candidate;
                    self.passes = true;
                }
                Err(ReadFailure::Predicate(original)) => {
                    self.plan = candidate;
                    return Err(ReadFailure::Predicate(original));
                }
                Err(ReadFailure::Source(original)) => return Err(ReadFailure::Source(original)),
            }
        }
        self.shapes(world)?;
        self.evidence(world)?;
        self.complete = true;
        Ok(())
    }
    fn shapes<W: MusubiRead>(
        &mut self,
        world: &W,
    ) -> Result<(), ReadFailure<W::Error, WorkRefusal>> {
        if self.shape_table == 0 {
            for original in world
                .musubi_archives_rows()
                .map_err(ReadFailure::Source)?
                .skip(self.shape_row)
            {
                let (_, row) = original.map_err(ReadFailure::Source)?;
                self.plan.shape(SourceShape::Archive(row))?;
                self.shape_row += 1;
                self.shape_part = 0;
            }
            self.shape_table = 1;
            self.shape_row = 0;
        }
        if self.shape_table == 1 {
            for original in world
                .musubi_provider_bundle_attestations_rows()
                .map_err(ReadFailure::Source)?
                .skip(self.shape_row)
            {
                let (_, row) = original.map_err(ReadFailure::Source)?;
                self.plan.shape(SourceShape::Attestation(row))?;
                self.shape_row += 1;
                self.shape_part = 0;
            }
            self.shape_table = 2;
            self.shape_row = 0;
        }
        if self.shape_table == 2 {
            for original in world
                .musubi_archive_locations_rows()
                .map_err(ReadFailure::Source)?
                .skip(self.shape_row)
            {
                let (_, row) = original.map_err(ReadFailure::Source)?;
                self.plan.shape(SourceShape::Location(row))?;
                self.shape_row += 1;
                self.shape_part = 0;
            }
            self.shape_table = 3;
            self.shape_row = 0;
        }
        if self.shape_table == 3 {
            for original in world
                .musubi_packages_rows()
                .map_err(ReadFailure::Source)?
                .skip(self.shape_row)
            {
                let (key, row) = original.map_err(ReadFailure::Source)?;
                if self.shape_part == 0 {
                    self.plan.shape(SourceShape::PackageId(key))?;
                    self.shape_part = 1;
                }
                self.plan.shape(SourceShape::Package(row))?;
                self.plan.nfc_scratch_bytes = self
                    .plan
                    .nfc_scratch_bytes
                    .max(row.claimed_namespace.validation_scratch_bytes());
                self.shape_row += 1;
                self.shape_part = 0;
            }
            self.shape_table = 4;
            self.shape_row = 0;
        }
        if self.shape_table == 4 {
            for original in world
                .musubi_releases_rows()
                .map_err(ReadFailure::Source)?
                .skip(self.shape_row)
            {
                let (key, row) = original.map_err(ReadFailure::Source)?;
                if self.shape_part == 0 {
                    self.plan.shape(SourceShape::ReleaseId(key))?;
                    self.shape_part = 1;
                }
                self.plan.shape(SourceShape::Release(row))?;
                self.shape_row += 1;
                self.shape_part = 0;
            }
            self.shape_table = 5;
            self.shape_row = 0;
        }
        if self.shape_table == 5 {
            for original in world
                .musubi_resolver_index_rows()
                .map_err(ReadFailure::Source)?
                .skip(self.shape_row)
            {
                let (key, row) = original.map_err(ReadFailure::Source)?;
                if self.shape_part == 0 {
                    self.plan.shape(SourceShape::ReleaseId(key))?;
                    self.shape_part = 1;
                }
                self.plan.shape(SourceShape::Resolver(row))?;
                self.shape_row += 1;
                self.shape_part = 0;
            }
            self.shape_table = 6;
            self.shape_row = 0;
        }
        if self.shape_table == 6 {
            for original in world
                .musubi_public_directory_rows()
                .map_err(ReadFailure::Source)?
                .skip(self.shape_row)
            {
                let (key, row) = original.map_err(ReadFailure::Source)?;
                if self.shape_part == 0 {
                    self.plan.shape(SourceShape::Selector(key))?;
                    self.shape_part = 1;
                }
                self.plan.shape(SourceShape::Directory(row))?;
                self.plan.nfc_scratch_bytes = self
                    .plan
                    .nfc_scratch_bytes
                    .max(row.selector.namespace.validation_scratch_bytes());
                self.shape_row += 1;
                self.shape_part = 0;
            }
            self.shape_table = 7;
            self.shape_row = 0;
        }
        Ok(())
    }
    fn evidence<W: MusubiRead>(
        &mut self,
        world: &W,
    ) -> Result<(), ReadFailure<W::Error, WorkRefusal>> {
        for original in world
            .musubi_archive_locations_rows()
            .map_err(ReadFailure::Source)?
            .skip(self.evidence_row)
        {
            let (_, location) = original.map_err(ReadFailure::Source)?;
            if location.state == MusubiArchiveLocationStateV1::Retired {
                self.evidence_row += 1;
                self.queries
                    .fill(crate::state::deserialize::musubi_source_read::LookupCursor::new());
                continue;
            }
            if self.evidence_part == 0 {
                // Preserve every repeated occurrence of the existing helper graph.
                for operation in [
                    Operation::ArchiveValidation,
                    Operation::LocationValidation,
                    Operation::ArchiveValidation,
                    Operation::OrderBindingValidation,
                    Operation::ArchiveValidation,
                    Operation::LocationValidation,
                    Operation::ProviderSetDigest,
                ] {
                    self.plan.operation(operation, 1)?;
                }
                self.evidence_part = 1;
            }
            if self.evidence_part == 1 {
                if let Some(row) = world
                    .musubi_locations_by_replication_order_get_retained(
                        &location.replication_order,
                        &mut self.queries[0],
                    )
                    .map_err(ReadFailure::Source)?
                {
                    self.plan.shape(SourceShape::OrderBinding(row))?;
                }
                self.evidence_part = 2;
            }
            if self.evidence_part == 2 {
                if let Some(row) = world
                    .pin_manifests_get_retained(&location.pin_manifest, &mut self.queries[1])
                    .map_err(ReadFailure::Source)?
                {
                    self.plan.shape(SourceShape::Pin(row))?;
                }
                self.evidence_part = 3;
            }
            if self.evidence_part == 3 {
                if let Some(row) = world
                    .replication_orders_get_retained(
                        &location.replication_order,
                        &mut self.queries[2],
                    )
                    .map_err(ReadFailure::Source)?
                {
                    self.plan.shape(SourceShape::Order(row))?;
                }
                self.evidence_part = 4;
            }
            for provider in &location.providers[self.provider..] {
                if self.provider_part == 0 {
                    if let Some(owner) = world
                        .provider_owners_get_retained(provider, &mut self.queries[3])
                        .map_err(ReadFailure::Source)?
                    {
                        self.plan.shape(SourceShape::Account(owner))?;
                    }
                    self.provider_part = 1;
                }
                let key = MusubiProviderBundleAttestationKeyV1 {
                    archive_id: location.archive_id,
                    replication_order: location.replication_order,
                    provider_id: *provider,
                };
                if let Some(record) = world
                    .musubi_provider_bundle_attestations_get_retained(&key, &mut self.queries[4])
                    .map_err(ReadFailure::Source)?
                {
                    for operation in [
                        Operation::AttestationRecordValidation,
                        Operation::AttestationValidation,
                        Operation::AttestationDigest,
                        Operation::AttestationValidation,
                        Operation::SigningHash,
                        Operation::AttestationDigest,
                    ] {
                        self.plan.operation(operation, 1)?;
                    }
                    self.plan.add(
                        WorkDimension::SignatureChecks,
                        record.attestation.approvals.len(),
                    )?;
                }
                self.provider += 1;
                self.queries[3].reset();
                self.queries[4].reset();
                self.provider_part = 0;
            }
            self.provider = 0;
            self.evidence_part = 0;
            self.evidence_row += 1;
            self.queries
                .fill(crate::state::deserialize::musubi_source_read::LookupCursor::new());
        }
        Ok(())
    }
}
