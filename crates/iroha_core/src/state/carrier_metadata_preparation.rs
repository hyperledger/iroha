//! Deterministic carrier metadata preparation within the State owner.
//!
//! This private continuation stages candidate-derived values only. Its caller
//! retains source/context admission, finality, event delivery and publication
//! authority; the method neither creates nor consumes any publication guard.

use super::*;

impl StateBlock<'_> {
    /// Stage the deterministic metadata selected by the caller's checked context.
    ///
    /// The native CommitQC owner supplies its exact ordered committee. This
    /// continuation cannot rotate it or run another lane lifecycle controller.
    #[allow(clippy::too_many_lines)]
    pub(super) fn prepare_deterministic_carrier_metadata(
        &mut self,
        signed_block: &SignedBlock,
        topology: Vec<PeerId>,
    ) -> Result<(), MergeLedgerCommitError> {
        let invalid = |reason: &str| {
            MergeLedgerCommitError::ExecutionBatchInvalid(format!(
                "carrier metadata preparation: {reason}"
            ))
        };
        let block_hash = signed_block.hash();
        if signed_block.header() != self._curr_block {
            return Err(invalid("proposal differs from the executed State scope"));
        }
        if signed_block
            .axt_envelopes()
            .is_some_and(|envelopes| envelopes.iter().any(|envelope| !envelope.spends.is_empty()))
        {
            return Err(invalid(
                "source-anchored AXT spends require finalized State admission",
            ));
        }
        let block_height: NonZeroUsize = signed_block
            .header()
            .height()
            .try_into()
            .map_err(|_| invalid("block height exceeds usize"))?;
        if self.block_hashes.len().checked_add(1) != Some(block_height.get())
            || signed_block.header().prev_block_hash() != self.block_hashes.last().copied()
        {
            return Err(invalid(
                "proposal does not extend its exact State predecessor",
            ));
        }
        validate_applied_npos_consensus_effects(
            signed_block.npos_consensus_effects(),
            self.applied_npos_consensus_effects_hash.as_ref(),
        )?;
        let snapshot = signed_block
            .axt_policy_snapshot()
            .ok_or_else(|| invalid("missing AXT policy snapshot"))?;
        snapshot
            .validate()
            .map_err(|error| invalid(&format!("AXT policy snapshot: {error}")))?;
        let committed_fragment_count = signed_block
            .committed_fragment_count()
            .ok_or_else(|| invalid("missing committed fragment count"))?;
        let transitions = signed_block
            .axt_transitioned_dataspaces()
            .ok_or_else(|| invalid("missing AXT transition set"))?;
        self.stage_prepaid_ordinary_carrier_membership(signed_block, block_height)?;
        if let Some(bundle) = signed_block.da_commitments() {
            let height = signed_block.header().height().get();
            self.pending_da_commitments = Some(PendingDaCommitmentBundle {
                block_height: height,
                bundle: bundle.clone(),
            });
        }
        if let Some(bundle) = signed_block.da_pin_intents() {
            let height = signed_block.header().height().get();
            self.stage_da_pin_intent_bundle(height, bundle.intents.clone())?;
        }
        let current_slot =
            current_axt_slot_from_block(&signed_block.header(), self.nexus.axt.slot_length_ms);
        if let Some(envelopes) = signed_block.axt_envelopes() {
            if !envelopes.is_empty() {
                iroha_logger::trace!(
                    count = envelopes.len(),
                    current_slot,
                    "persisting AXT envelopes from committed block"
                );
                self.apply_replayed_axt_envelopes(envelopes, current_slot)
                    .map_err(|error| invalid(&format!("AXT replay: {error}")))?;
            }
        }
        self.block_hashes.push(block_hash);
        self.stage_musubi_resolver_index_checkpoint(
            signed_block.header().height().get(),
            block_hash,
        )?;
        // Preserve the exact current and previous ordered committees supplied by
        // the sole native schedule. A post-commit rotation would change C_h.
        let previous = self.commit_topology.take_vec();
        self.prev_commit_topology
            .mutate_vec(|value| *value = previous);
        self.commit_topology.mutate_vec(|value| *value = topology);
        // This height/hash-bound record maintains the physical runtime snapshot's
        // strict current/predecessor accounting. Lane selection is owned solely
        // by World.sumeragi_lanes and has already executed in the native step.
        // TODO: remove the dormant Nexus autoscale record layout with its remaining
        // configuration and snapshot schema consumers; no controller runs here.
        self.stage_autoscale_sample_record_for_count(signed_block, committed_fragment_count)
            .map_err(|error| invalid(&format!("runtime work sample: {error}")))?;
        self.axt_authorization_transitioned.clone_from(transitions);
        self.replace_axt_policy_projection(snapshot);
        self.finalize_axt_policy_transition_ratchets()
            .map_err(|error| invalid(&format!("AXT counter ratchets: {error}")))?;
        self.install_axt_policy_snapshot(snapshot)
            .map_err(|error| invalid(&format!("AXT policy projection: {error}")))?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "carrier_metadata_preparation_tests.rs"]
mod tests;
