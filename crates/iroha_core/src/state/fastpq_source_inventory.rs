//! Validator-owned FASTPQ inventory reconciled against applied execution sources.

#[cfg(test)]
use std::collections::BTreeMap;
use std::{collections::BTreeSet, sync::Arc};

use iroha_data_model::fastpq::FastpqSourceStatementContextV1;

use super::{Hash, StateBlock, output_capacity::OwnedExecutionSources};
use crate::fastpq::FastpqSourceExecutionEntryV1;
#[cfg(test)]
use crate::fastpq::{
    FastpqSourceStatementBuildLimits, TransferArchiveDiagnostic, TransferEntryDiagnostic,
    prepare_transfer_archive_diagnostic,
};
#[cfg(test)]
use crate::queue::RoutingDecision;
#[cfg(test)]
use iroha_data_model::transaction::TransactionEntrypoint;
#[cfg(test)]
use iroha_model_base::topology::DataSpaceId;

mod content_verification;
// Unanchored transfer preparation diagnostics have no shipping D7/wire surface.
#[cfg(test)]
mod owned_transfer_diagnostic;
mod public_seal;
#[cfg(test)]
mod statement_reservation;
use public_seal::{SourceTranscriptSeal, seal_public_transcripts};

/// Complete local source projection captured by a validator's block execution.
///
/// Entries are the actual producer-owned Network, Pipeline and Time calls in
/// canonical output order, followed by applied protocol-purpose sources in hash
/// order. This is not the physical order of state fragments. Rejected and
/// zero-transcript calls remain present; a transcript capture does not invent an
/// additional execution call. Protocol work without a transcript is not a proof
/// source. Applied SNS maintenance and retained governance share the public
/// ProtocolPurpose kind but final reconciliation requires exactly one private
/// native or governance quota owner for every purpose; the kind grants neither.
///
/// Private construction prevents a supplied archive from becoming an owned
/// inventory. The seal retains exact finalized public occurrences while excluding
/// private SMT paths. This local record is not a finality attestation or admission token.
/// Later applied transcript capture invalidates final witness capture. The seal
/// does not freeze unrelated ledger effects or authenticate source finality.
/// Final raw and retained ordinary transcript contents must match this seal before
/// capture, extraction or commit.
/// Mandatory D7 custody independently retains the complete effect journal and is joined
/// to native finality by the move-only captured-source owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FastpqSourceInventoryV1 {
    source: FastpqSourceStatementContextV1,
    entries: Vec<FastpqSourceExecutionEntryV1>,
    transcript_entry_hashes: BTreeSet<Hash>,
    transcript_seal: SourceTranscriptSeal,
    tx_set_hash: [u8; 32],
}

/// Fixed local custody retained by State through capture, extraction and commit.
/// The private seal retains all three original ledger allocations; an equal rebuilt
/// journal or inventory cannot recover authority after any observed mismatch.
pub(super) struct SourceQuotaInventorySeal {
    inventory: Arc<FastpqSourceInventoryV1>,
    quota: crate::fastpq::source_reservation::admission::SourceQuotaSeal,
    failed: std::sync::atomic::AtomicBool,
}

impl SourceQuotaInventorySeal {
    fn verify(
        &self,
        block: &StateBlock<'_>,
        inventory: &Arc<FastpqSourceInventoryV1>,
    ) -> Result<(), String> {
        use std::sync::atomic::Ordering;
        let valid = Arc::ptr_eq(&self.inventory, inventory)
            && block
                .fastpq_source_policy_at_block_start
                .is_some_and(|(profile, output)| {
                    block.fastpq_source_quota.as_ref().is_some_and(|quota| {
                        quota
                            .as_ref()
                            .is_ok_and(|quota| quota.matches_retained(&self.quota, profile, output))
                    })
                });
        if !valid {
            self.failed.store(true, Ordering::Relaxed);
        }
        if self.failed.load(Ordering::Relaxed) {
            return Err(
                "FASTPQ source quota ownership changed after inventory finalization".into(),
            );
        }
        Ok(())
    }
}

impl FastpqSourceInventoryV1 {
    /// Frozen network and height of this inventory.
    pub const fn source(&self) -> FastpqSourceStatementContextV1 {
        self.source
    }

    /// Complete ordered source projection, including block entries without transfers.
    pub fn entries(&self) -> &[FastpqSourceExecutionEntryV1] {
        &self.entries
    }

    /// Exact applied transcript keys required by source-manifest construction.
    pub fn transcript_entry_hashes(&self) -> &BTreeSet<Hash> {
        &self.transcript_entry_hashes
    }

    /// Authoritative ordered canonical transaction-wire commitment supplied by block execution.
    pub const fn tx_set_hash(&self) -> [u8; 32] {
        self.tx_set_hash
    }

    /// Test-only preparation of the live transfer relation against the retained public seal.
    /// This verifies original bundle ownership but returns no D7 value or native authority.
    #[cfg(test)]
    pub(crate) fn prepare_transfer_diagnostic(
        &self,
        slot: u64,
        perm_root: [u8; 32],
        transcripts: &BTreeMap<Hash, Vec<iroha_data_model::fastpq::TransferTranscript>>,
        limits: FastpqSourceStatementBuildLimits,
    ) -> Result<(TransferArchiveDiagnostic, Vec<TransferEntryDiagnostic>), String> {
        if !self.transcript_entry_hashes.iter().eq(transcripts.keys()) {
            return Err("FASTPQ manifest transcript keys differ from the owned inventory".into());
        }
        crate::fastpq::preflight_fastpq_source_transcripts(transcripts, limits)?;
        if seal_public_transcripts(transcripts)? != self.transcript_seal {
            return Err(
                "FASTPQ manifest public transcripts differ from the owned inventory seal".into(),
            );
        }
        prepare_transfer_archive_diagnostic(
            self.source,
            &self.entries,
            slot,
            perm_root,
            self.tx_set_hash,
            transcripts,
            limits,
        )
    }
}

impl StateBlock<'_> {
    /// Seal actual Network/Pipeline/Time sources before draining their transcripts.
    ///
    /// The nonconstructible capsule belongs to the completed applying producer.
    /// Rejected calls remain valid owners of separately applied fee/penalty work;
    /// this method never derives capture authority from the result disposition.
    /// Every mismatch is latched before any partial inventory can be published.
    pub(super) fn finalize_owned_fastpq_source_inventory_with_pending(
        &mut self,
        sources: &OwnedExecutionSources,
        pending: Option<crate::fastpq::PendingTransferTranscriptDigests>,
    ) -> Result<(), crate::execution_attempt::ExecutionAttemptError<String>> {
        let result = self.finalize_fastpq_source_inventory_from(
            pending,
            |state| state.validate_owned_fastpq_sources(sources),
            |state, tx_set_hash| state.build_owned_fastpq_source_inventory(sources, tx_set_hash),
        );
        // Only this original completed producer may retain the quantity census.
        // Diagnostic incompleteness never grants D7 authority or changes business results.
        match result {
            Ok(()) => {
                // Mandatory original source commitment is admitted before optional
                // archive retention; physical refusal leaves no consensus result.
                self.retain_finalized_quantity_source()?;
                self.retain_quantity_source_census();
                Ok(())
            }
            Err(error) => {
                self.reject_quantity_source_census();
                Err(crate::execution_attempt::ExecutionAttemptError::Rejected(
                    error,
                ))
            }
        }
    }

    fn validate_owned_fastpq_sources(&self, sources: &OwnedExecutionSources) -> Result<(), String> {
        if sources.proposal() != self._curr_block.hash() {
            return Err("FASTPQ owned sources belong to another proposal".into());
        }
        let frozen = self
            .fastpq_source_context
            .as_ref()
            .ok_or("FASTPQ inventory has no frozen source-height context")?;
        if sources.source_context() != frozen.source
            || frozen.source.network_id != self.network_id
            || frozen.source.height != self._curr_block.height().get()
        {
            return Err(
                "FASTPQ owned sources differ from the applying source-height context".into(),
            );
        }
        let routes = sources.network_routes();
        if routes.len() > sources.entries().len() {
            return Err("FASTPQ owned Network routes exceed the actual source count".into());
        }
        for (source, route) in sources.entries().iter().zip(routes) {
            if source.lane() != Some(route.lane_id) || source.dataspace() != route.dataspace_id {
                return Err("FASTPQ owned Network source differs from its frozen route".into());
            }
        }
        let internal = &sources.entries()[routes.len()..];
        if internal.is_empty() != sources.internal_dataspace().is_none() {
            return Err("FASTPQ internal source lost its original root namespace".into());
        }
        for source in internal {
            if source.lane().is_some() || Some(source.dataspace()) != sources.internal_dataspace() {
                return Err(
                    "FASTPQ internal source differs from its actual unrouted execution".into(),
                );
            }
        }
        Ok(())
    }

    /// Fixture-only source construction, including the inactive native prefix.
    /// Supplied calls here are not an ordinary production acceptance authority.
    #[cfg(test)]
    pub(crate) fn finalize_fastpq_source_inventory(
        &mut self,
        external: &[TransactionEntrypoint],
        routing: &[RoutingDecision],
        time_calls: &[Hash],
    ) -> Result<(), String> {
        self.finalize_fastpq_source_inventory_with_pending(external, routing, time_calls, None)
    }

    /// Preserve existing exact native-prefix and transcript fixture controls.
    /// Production callers must consume the actual producer-owned capsule instead.
    #[cfg(test)]
    pub(crate) fn finalize_fastpq_source_inventory_with_pending(
        &mut self,
        external: &[TransactionEntrypoint],
        routing: &[RoutingDecision],
        time_calls: &[Hash],
        pending: Option<crate::fastpq::PendingTransferTranscriptDigests>,
    ) -> Result<(), String> {
        self.finalize_fastpq_source_inventory_from(
            pending,
            |_| Ok(()),
            |state, tx_set_hash| {
                state.build_fastpq_source_inventory(external, routing, time_calls, tx_set_hash)
            },
        )
    }

    /// Shared exact digest/seal/latch boundary; source authority is checked first.
    fn finalize_fastpq_source_inventory_from(
        &mut self,
        pending: Option<crate::fastpq::PendingTransferTranscriptDigests>,
        validate: impl FnOnce(&Self) -> Result<(), String>,
        build: impl FnOnce(&Self, [u8; 32]) -> Result<FastpqSourceInventoryV1, String>,
    ) -> Result<(), String> {
        if self.fastpq_source_inventory.is_some() {
            return Err("FASTPQ source inventory has already been finalized".into());
        }
        let inventory = validate(self).and_then(|()| {
            if matches!(
                self.execution_output_plan,
                Some(super::output_capacity::ExecutionOutputPlanState::Poisoned)
            ) {
                return Err("FASTPQ source inventory cannot finalize a poisoned carrier".into());
            }
            let tx_set_hash = self
                .fastpq_tx_set_hash
                .filter(|hash| *hash != [0; 32])
                .ok_or_else(|| {
                    crate::fastpq::TranscriptBatchError::MissingTransactionSetCommitment.to_string()
                })?;
            // Check shape and supplied digests before legacy digest finalization.
            self.validate_fastpq_source_transcript_shape()?;
            crate::fastpq::validate_precomputed_transfer_transcript_digests_in_map(
                &self.fastpq_transcripts,
            )?;
            crate::fastpq::finalize_transfer_transcript_digests_in_map_with_pending(
                &mut self.fastpq_transcripts,
                pending,
            );
            let inventory = build(self, tx_set_hash)?;
            let quota = self
                .fastpq_source_quota
                .as_ref()
                .ok_or("source capacity was not frozen")?
                .as_ref()
                .map_err(|error| error.clone())?
                .reconcile_and_retain(inventory.entries(), &self.fastpq_transcripts)?;
            self.fastpq_source_captures
                .seal()
                .map_err(|error| error.to_string())?;
            Ok((inventory, quota))
        });
        match inventory {
            Ok((inventory, quota)) => {
                self.fastpq_entry_dataspaces = inventory
                    .entries
                    .iter()
                    .map(|entry| (entry.entry_hash, entry.dataspace_id))
                    .collect();
                let inventory = Arc::new(inventory);
                self.fastpq_source_quota_seal = Some(SourceQuotaInventorySeal {
                    inventory: Arc::clone(&inventory),
                    quota,
                    failed: std::sync::atomic::AtomicBool::new(false),
                });
                self.fastpq_source_inventory = Some(Ok(inventory));
                Ok(())
            }
            Err(error) => {
                self.execution_output_plan =
                    Some(super::output_capacity::ExecutionOutputPlanState::Poisoned);
                self.fastpq_source_inventory = Some(Err(error.clone()));
                Err(error)
            }
        }
    }

    fn build_owned_fastpq_source_inventory(
        &self,
        sources: &OwnedExecutionSources,
        tx_set_hash: [u8; 32],
    ) -> Result<FastpqSourceInventoryV1, String> {
        let frozen = self
            .fastpq_source_context
            .as_ref()
            .ok_or("FASTPQ inventory has no frozen source-height context")?;
        let captures = self
            .captured_fastpq_transcript_sources()
            .map_err(ToString::to_string)?;
        if !captures.keys().eq(self.fastpq_transcripts.keys()) {
            return Err("FASTPQ applied source keys differ from the transcript accumulator".into());
        }
        if u32::try_from(sources.entries().len()).is_err() {
            return Err("FASTPQ source inventory entry count exceeds u32".into());
        }
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(sources.entries().len())
            .map_err(|_| "host cannot retain owned FASTPQ sources")?;
        let mut identities = BTreeSet::new();
        for source in sources.entries() {
            let call = source.call();
            if !identities.insert(call) {
                return Err(
                    "FASTPQ source inventory contains a duplicate execution identity".into(),
                );
            }
            let expected = frozen
                .capture_transcript(Some(call), call, source.lane(), Some(source.dataspace()), 0)
                .map_err(|error| error.to_string())?;
            if let Some(captured) = captures.get(&call) {
                if captured.entry_hash() != call
                    || captured.source() != expected.source()
                    || captured.route() != expected.route()
                    || captured.dataspace_id() != expected.dataspace_id()
                    || captured.execution_kind() != expected.execution_kind()
                {
                    return Err("FASTPQ block entry differs from its applied source context".into());
                }
            }
            entries.push(FastpqSourceExecutionEntryV1 {
                entry_hash: call,
                execution_kind: expected.execution_kind(),
                route: expected.route(),
                dataspace_id: expected.dataspace_id(),
            });
        }
        // Applied captures are already in hash order. An unknown execution call
        // cannot manufacture an invocation omitted by the actual output owner.
        for (hash, captured) in captures {
            if captured.source() != frozen.source || captured.entry_hash() != *hash {
                return Err("FASTPQ captured source differs from the frozen block scope".into());
            }
            if identities.contains(hash) {
                continue;
            }
            if !captured.is_protocol_purpose() {
                return Err("FASTPQ transcript has no owned execution call".into());
            }
            if entries.len() >= u32::MAX as usize {
                return Err("FASTPQ additional source identity or count is invalid".into());
            }
            entries
                .try_reserve(1)
                .map_err(|_| "host cannot retain FASTPQ protocol sources")?;
            entries.push(FastpqSourceExecutionEntryV1 {
                entry_hash: *hash,
                execution_kind: captured.execution_kind(),
                route: captured.route(),
                dataspace_id: captured.dataspace_id(),
            });
        }
        Ok(FastpqSourceInventoryV1 {
            source: frozen.source,
            entries,
            transcript_entry_hashes: captures.keys().copied().collect(),
            transcript_seal: seal_public_transcripts(&self.fastpq_transcripts)?,
            tx_set_hash,
        })
    }

    fn validate_fastpq_source_transcript_shape(&self) -> Result<(), String> {
        for (hash, bundle) in &self.fastpq_transcripts {
            if bundle.is_empty()
                || bundle.iter().any(|transcript| {
                    transcript.batch_hash != *hash || transcript.deltas.is_empty()
                })
            {
                return Err(
                    "FASTPQ inventory contains an empty or misidentified transcript".into(),
                );
            }
        }
        Ok(())
    }

    #[cfg(test)]
    fn build_fastpq_source_inventory(
        &self,
        external: &[TransactionEntrypoint],
        routing: &[RoutingDecision],
        time_calls: &[Hash],
        tx_set_hash: [u8; 32],
    ) -> Result<FastpqSourceInventoryV1, String> {
        if external.len() != routing.len() {
            return Err("FASTPQ external entrypoints do not align with validated routes".into());
        }
        let frozen = self
            .fastpq_source_context
            .as_ref()
            .ok_or_else(|| "FASTPQ inventory has no frozen source-height context".to_owned())?;
        let captures = self
            .captured_fastpq_transcript_sources()
            .map_err(ToString::to_string)?;
        if !captures.keys().eq(self.fastpq_transcripts.keys()) {
            return Err("FASTPQ applied source keys differ from the transcript accumulator".into());
        }
        let mut entries = Vec::new();
        let mut identities = BTreeSet::new();
        let mut push = |entry: FastpqSourceExecutionEntryV1| -> Result<(), String> {
            if !identities.insert(entry.entry_hash) {
                return Err(
                    "FASTPQ source inventory contains a duplicate execution identity".into(),
                );
            }
            if entries.len() >= u32::MAX as usize {
                return Err("FASTPQ source inventory entry count exceeds u32".into());
            }
            entries.push(entry);
            Ok(())
        };
        let ordinary = external.iter().zip(routing).map(|(entry, route)| {
            Ok::<_, String>((
                Hash::from(entry.execution_call_hash()),
                Some(route.lane_id),
                route.dataspace_id,
            ))
        });
        for source in ordinary.chain(
            time_calls
                .iter()
                .map(|hash| Ok((*hash, None, DataSpaceId::UNIVERSAL))),
        ) {
            let (hash, lane, dataspace) = source?;
            let expected = frozen
                .capture_transcript(Some(hash), hash, lane, Some(dataspace), 0)
                .map_err(|error| error.to_string())?;
            if let Some(captured) = captures.get(&hash) {
                if captured.source() != expected.source()
                    || captured.route() != expected.route()
                    || captured.dataspace_id() != expected.dataspace_id()
                    || captured.execution_kind() != expected.execution_kind()
                {
                    return Err("FASTPQ block entry differs from its applied source context".into());
                }
            }
            push(FastpqSourceExecutionEntryV1 {
                entry_hash: hash,
                execution_kind: expected.execution_kind(),
                route: expected.route(),
                dataspace_id: dataspace,
            })?;
        }
        // The capture map is sorted by hash, independently of apply scheduling or
        // shared fragment indices. Do not infer physical execution order from it.
        for (hash, captured) in captures {
            if captured.source() != frozen.source || captured.entry_hash() != *hash {
                return Err("FASTPQ captured source differs from the frozen block scope".into());
            }
            if identities.contains(hash) {
                continue;
            }
            if !identities.insert(*hash) || entries.len() >= u32::MAX as usize {
                return Err("FASTPQ additional source identity or count is invalid".into());
            }
            entries.push(FastpqSourceExecutionEntryV1 {
                entry_hash: *hash,
                execution_kind: captured.execution_kind(),
                route: captured.route(),
                dataspace_id: captured.dataspace_id(),
            });
        }
        Ok(FastpqSourceInventoryV1 {
            source: frozen.source,
            entries,
            transcript_entry_hashes: captures.keys().copied().collect(),
            transcript_seal: seal_public_transcripts(&self.fastpq_transcripts)?,
            tx_set_hash,
        })
    }

    /// Read the sealed local inventory, or its first construction or final content failure.
    ///
    /// `None` means the execution path has not sealed an inventory. Authenticated
    /// replay does not manufacture a local inventory from advertised proof data.
    ///
    /// # Errors
    /// Returns the first latched construction or final witness content failure without
    /// exposing a partial or invalidated inventory.
    pub fn fastpq_source_inventory(&self) -> Result<Option<&FastpqSourceInventoryV1>, &str> {
        match &self.fastpq_source_inventory {
            None => Ok(None),
            Some(Ok(inventory)) => Ok(Some(inventory)),
            Some(Err(error)) => Err(error.as_str()),
        }
    }

    /// Require the same locally owned sealed source projection at final witness capture.
    ///
    /// Applied captures remain sealed after transcript draining. Any later applied
    /// occurrence invalidates this check, including another occurrence under an
    /// existing key. Empty or rolled-back transactions do not invent new sources.
    /// This method never reconstructs ownership from advertised witness contents.
    ///
    /// # Errors
    /// Rejects missing inventory, failed construction or final witness content verification,
    /// late applied captures,
    /// changed frozen source context, or disagreement with the retained source caches.
    pub(crate) fn verified_fastpq_source_inventory_for_capture(
        &self,
    ) -> Result<Arc<FastpqSourceInventoryV1>, String> {
        #[cfg(test)]
        if matches!(
            self.execution_output_plan,
            Some(super::output_capacity::ExecutionOutputPlanState::Inspecting)
        ) {
            return Err("FASTPQ witness capture refuses a source inspection carrier".into());
        }
        if matches!(
            self.execution_output_plan,
            Some(super::output_capacity::ExecutionOutputPlanState::Poisoned)
        ) {
            return Err("FASTPQ witness capture refuses a poisoned carrier".into());
        }
        let inventory = match &self.fastpq_source_inventory {
            None => return Err("FASTPQ witness capture has no finalized owned inventory".into()),
            Some(Err(error)) => return Err(error.clone()),
            Some(Ok(inventory)) => inventory,
        };
        self.fastpq_source_quota_seal
            .as_ref()
            .ok_or("FASTPQ witness capture has no retained original quota journals")?
            .verify(self, inventory)?;
        let captures = self
            .fastpq_source_captures
            .sealed_sources()
            .map_err(|error| error.to_string())?;
        let frozen = self.fastpq_source_context.as_ref().ok_or_else(|| {
            "FASTPQ witness capture has no frozen source-height context".to_owned()
        })?;
        if inventory.source != frozen.source
            || inventory.source.network_id != self.network_id
            || inventory.source.height != self._curr_block.height().get()
        {
            return Err(
                "FASTPQ witness capture differs from its sealed source-height context".into(),
            );
        }
        if !inventory.transcript_entry_hashes.iter().eq(captures.keys()) {
            return Err("FASTPQ witness capture keys differ from the owned inventory".into());
        }
        if self.fastpq_tx_set_hash != Some(inventory.tx_set_hash)
            || self.fastpq_entry_dataspaces.len() != inventory.entries.len()
        {
            return Err(
                "FASTPQ witness capture source caches differ from the owned inventory".into(),
            );
        }
        for entry in &inventory.entries {
            if self.fastpq_entry_dataspaces.get(&entry.entry_hash) != Some(&entry.dataspace_id) {
                return Err(
                    "FASTPQ witness capture dataspace cache differs from the owned inventory"
                        .into(),
                );
            }
            if let Some(captured) = captures.get(&entry.entry_hash) {
                if captured.source() != inventory.source
                    || captured.entry_hash() != entry.entry_hash
                    || captured.route() != entry.route
                    || captured.dataspace_id() != entry.dataspace_id
                    || captured.execution_kind() != entry.execution_kind
                {
                    return Err(
                        "FASTPQ witness capture execution source differs from the owned inventory"
                            .into(),
                    );
                }
            }
        }
        Ok(Arc::clone(inventory))
    }
}

#[cfg(test)]
mod capture_tests;
#[cfg(test)]
mod commit_tests;
#[cfg(test)]
mod content_capture_tests;
#[cfg(test)]
mod precomputed_digest_tests;
#[cfg(test)]
mod recorder_isolation_tests;
#[cfg(test)]
mod tests;

#[cfg(test)]
mod owned_sources_tests;

#[cfg(test)]
pub(crate) mod native_capture_fixture;
