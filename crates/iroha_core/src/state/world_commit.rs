//! Move-only preparation of the exact World overlay published by State commit.
//!
//! Late DA writes and lifecycle cleanup finish before the overlay is captured by
//! tiered persistence or consumed by publication. A rebuildable DA cache never
//! decides which authoritative World records exist. The prepared owner exposes
//! no mutable World access, so its World state accumulator and its commit see
//! the same values. Existing State authorization and transaction gates still own
//! permission to publish; this object cannot authorize a carrier by itself.
//!
//! The State publisher advances the World state accumulator from this
//! completed overlay (`WorldBlock::advance_state_accumulator`) after these
//! writes, so the accumulator covers every deterministic tail write.

use super::*;
use crate::execution_attempt::ExecutionAttemptError;

/// Observe the two actual pure validators on the calling native test thread.
/// The guard restores the prior observation on normal return and unwind.
#[cfg(test)]
pub(super) mod validation_observer {
    use std::cell::Cell;

    thread_local! {
        static COUNTS: Cell<Option<[usize; 2]>> = const { Cell::new(None) };
    }

    pub(in crate::state) fn observe<R>(action: impl FnOnce() -> R) -> R {
        struct Restore(Option<[usize; 2]>);
        impl Drop for Restore {
            fn drop(&mut self) {
                COUNTS.with(|counts| counts.set(self.0));
            }
        }
        let restore = Restore(COUNTS.with(|counts| counts.replace(Some([0; 2]))));
        let result = action();
        drop(restore);
        result
    }

    pub(in crate::state) fn counts() -> [usize; 2] {
        COUNTS.with(|counts| counts.get().expect("active validator observation"))
    }

    pub(super) fn record(index: usize) {
        COUNTS.with(|counts| {
            if let Some(mut observed) = counts.get() {
                observed[index] += 1;
                counts.set(Some(observed));
            }
        });
    }

    #[test]
    fn nested_validation_observation_restores_original_counts_after_unwind() {
        observe(|| {
            record(0);
            let original = counts();
            observe(|| {
                record(1);
                assert_eq!(counts(), [0, 1]);
            });
            assert_eq!(counts(), original);
            assert!(
                std::panic::catch_unwind(|| {
                    observe(|| {
                        record(1);
                        panic!("test-only validator observation unwind");
                    });
                })
                .is_err()
            );
            assert_eq!(counts(), original);
        });
        assert!(COUNTS.with(|counts| counts.get().is_none()));
    }
}

/// One finalized World overlay and its derived DA cache publication records.
///
/// Production uses only the associated deterministic-tail functions on the State's own
/// overlay; a prepared instance is a component fixture.
pub(in crate::state) struct PreparedWorldCommit<'state> {
    #[cfg(test)]
    state: &'state State,
    #[cfg(test)]
    world: WorldBlock<'state>,
    #[cfg(test)]
    effects: PreparedWorldEffects,
    /// The World lifetime of the associated functions.
    _world: core::marker::PhantomData<&'state ()>,
}

/// Deferred cache records from the exact prepared World; no publication authority.
/// The consuming carrier owner retains these alongside its immutable World.
pub(in crate::state) struct PreparedWorldEffects {
    da_pins: Vec<DaPinIntentWithLocation>,
}

impl PreparedWorldEffects {
    /// Borrow every deferred record and its original vector capacity for admission.
    /// This view allocates nothing and cannot publish or change the prepared tail.
    pub(in crate::state) fn admission_pins(&self) -> &Vec<DaPinIntentWithLocation> {
        let Self { da_pins } = self;
        da_pins
    }

    /// Consume the exact deferred cache records after their World is published.
    /// The enclosing State publisher retains all authorization and writer gates.
    pub(in crate::state) fn publish(
        self,
        state: &State,
        cache: &mut DaPinStore,
        releases: &mut view_acquisition::WorldReadReleases,
    ) {
        state.publish_prepared_da_pins(self.da_pins, cache, releases);
    }
}

impl<'state> PreparedWorldCommit<'state> {
    /// Finish late deterministic writes before any live World/cache publication.
    #[cfg(test)]
    pub(in crate::state) fn prepare(
        state: &'state State,
        mut world: WorldBlock<'state>,
        block_height: u64,
        nexus: &iroha_config::parameters::actual::Nexus,
        activation_heights: &BTreeMap<LaneId, u64>,
        pending_pins: Option<&PendingDaPinIntentBundle>,
        pending_lifecycle: Option<&PendingAutoscaleLaneLifecycle>,
    ) -> Result<Self, ExecutionAttemptError<String>> {
        let effects = Self::prepare_overlay(
            &mut world,
            &state.ivm_execution_budget(),
            block_height,
            nexus,
            activation_heights,
            pending_pins,
            pending_lifecycle,
        )?;
        Ok(Self {
            state,
            world,
            effects,
            _world: core::marker::PhantomData,
        })
    }

    /// Finish the same deterministic tail while the consuming carrier still
    /// owns every State journal. Its returned effects are retained by that
    /// read-only owner; they cannot publish or make an unprepared World valid.
    #[cfg(test)]
    pub(in crate::state) fn prepare_overlay(
        world: &mut WorldBlock<'state>,
        execution_budget: &iroha_allocation::AllocationBudget,
        block_height: u64,
        nexus: &iroha_config::parameters::actual::Nexus,
        activation_heights: &BTreeMap<LaneId, u64>,
        pending_pins: Option<&PendingDaPinIntentBundle>,
        pending_lifecycle: Option<&PendingAutoscaleLaneLifecycle>,
    ) -> Result<PreparedWorldEffects, ExecutionAttemptError<String>> {
        let effects = Self::prepare_overlay_mutations(
            world,
            block_height,
            nexus,
            activation_heights,
            pending_pins,
            pending_lifecycle,
        )?;
        Self::validate_prepared_overlay(world, execution_budget)?;
        Ok(effects)
    }

    /// Complete the deterministic private tail exactly once; retain the returned original
    /// effects before running any validation that may defer for local resources.
    pub(in crate::state) fn prepare_overlay_mutations(
        world: &mut WorldBlock<'state>,
        block_height: u64,
        nexus: &iroha_config::parameters::actual::Nexus,
        activation_heights: &BTreeMap<LaneId, u64>,
        pending_pins: Option<&PendingDaPinIntentBundle>,
        pending_lifecycle: Option<&PendingAutoscaleLaneLifecycle>,
    ) -> Result<PreparedWorldEffects, ExecutionAttemptError<String>> {
        if pending_pins.is_some_and(|pending| pending.block_height != block_height) {
            return Err("prepared DA pin bundle belongs to a different block height".into());
        }
        let da_pins = match pending_pins {
            Some(pending) => {
                Self::prepare_pins(world, nexus, activation_heights, pending, pending_lifecycle)?
            }
            None => Vec::new(),
        };
        if let Some(pending) = pending_pins {
            for (key, value) in &pending.quota_writes {
                world
                    .smart_contract_state
                    .insert(key.clone(), value.clone());
            }
        }
        for record in &da_pins {
            Self::apply_pin(world, record);
        }
        if let Some(pending) = pending_lifecycle {
            State::prune_lane_lifecycle_world_block_state_for_lanes(
                world,
                &pending.catalog_update.lanes_to_reset,
            );
        }
        Ok(PreparedWorldEffects { da_pins })
    }

    /// Validate the same completed immutable World. A local capacity refusal does not
    /// recreate quota writes, pin records, lifecycle pruning or their allocations.
    #[cfg(test)]
    pub(in crate::state) fn validate_prepared_overlay(
        world: &WorldBlock<'state>,
        execution_budget: &iroha_allocation::AllocationBudget,
    ) -> Result<(), ExecutionAttemptError<String>> {
        Self::validate_prepared_policy_transition(world)?;
        Self::validate_prepared_musubi(world, execution_budget)
    }

    /// Keep the original policy-transition prefix on every publication attempt.
    pub(in crate::state) fn validate_prepared_policy_transition(
        world: &WorldBlock<'state>,
    ) -> Result<(), ExecutionAttemptError<String>> {
        super::retail_daily_limit_state::validate_immutable_policy_transition(world)
            .map_err(crate::execution_attempt::ExecutionAttemptError::Rejected)
    }

    /// Fixture convenience preserves the original live-before-universal order.
    #[cfg(test)]
    pub(in crate::state) fn validate_prepared_musubi(
        world: &WorldBlock<'state>,
        execution_budget: &iroha_allocation::AllocationBudget,
    ) -> Result<(), ExecutionAttemptError<String>> {
        Self::validate_prepared_musubi_live(world, execution_budget)?;
        Self::validate_prepared_musubi_universal(world, execution_budget)
    }

    /// Exact immutable dependency set shared by the two original validators.
    fn requires_musubi_validation(world: &WorldBlock<'state>) -> bool {
        world.musubi_archives.is_dirty()
            || world.musubi_archive_locations.is_dirty()
            || world.musubi_provider_bundle_attestations.is_dirty()
            || world.musubi_locations_by_pin.is_dirty()
            || world.musubi_locations_by_replication_order.is_dirty()
            || world.musubi_locations_by_provider.is_dirty()
            || world.pin_manifests.is_dirty()
            || world.replication_orders.is_dirty()
            || world.provider_owners.is_dirty()
            || world.musubi_archive_availability.is_dirty()
            || world.musubi_packages.is_dirty()
            || world.musubi_releases.is_dirty()
            || world.musubi_resolver_index.is_dirty()
            || world.musubi_public_directory.is_dirty()
            || world.musubi_resolver_index_revision.is_dirty()
    }

    /// Finish the original live projection pass, retaining no scratch after success.
    /// Only its enclosing immutable publisher can reuse that same-cut success.
    pub(in crate::state) fn validate_prepared_musubi_live(
        world: &WorldBlock<'state>,
        execution_budget: &iroha_allocation::AllocationBudget,
    ) -> Result<(), ExecutionAttemptError<String>> {
        if Self::requires_musubi_validation(world) {
            #[cfg(test)]
            validation_observer::record(0);
            deserialize::validate_musubi_live_projection_cut(world, execution_budget).map_err(
                |error| {
                    error
                        .map_rejection(|error| format!("Musubi World publication refused: {error}"))
                },
            )?;
        }
        Ok(())
    }

    /// Preserve package-identity-before-scratch order in the original universal pass.
    /// A refusal advances no universal stage and changes no source or pool authority.
    pub(in crate::state) fn validate_prepared_musubi_universal(
        world: &WorldBlock<'state>,
        execution_budget: &iroha_allocation::AllocationBudget,
    ) -> Result<(), ExecutionAttemptError<String>> {
        if Self::requires_musubi_validation(world) {
            #[cfg(test)]
            validation_observer::record(1);
            deserialize::musubi_universal::validate_musubi_universal_projection_cut(
                world,
                deserialize::musubi_rejection::ProjectionCut::Candidate,
                execution_budget,
            )
            .map_err(|error| {
                error.map_rejection(|error| format!("Musubi World publication refused: {error}"))
            })?;
        }
        Ok(())
    }

    /// Read the completed overlay; no subsequent caller mutation is possible.
    #[cfg(test)]
    pub(in crate::state) fn world(&self) -> &WorldBlock<'state> {
        &self.world
    }

    /// Consume the same prepared World after State's publication gates succeed.
    #[cfg(test)]
    pub(in crate::state) fn commit(self) {
        let mut releases = view_acquisition::WorldReadReleases::new(&self.state.world);
        self.world.commit();
        self.effects.publish(
            self.state,
            &mut self.state.da_pin_intents.write(),
            &mut releases,
        );
    }

    fn prepare_pins(
        world: &WorldBlock<'_>,
        nexus: &iroha_config::parameters::actual::Nexus,
        activation_heights: &BTreeMap<LaneId, u64>,
        pending: &PendingDaPinIntentBundle,
        lifecycle: Option<&PendingAutoscaleLaneLifecycle>,
    ) -> Result<Vec<DaPinIntentWithLocation>, String> {
        let effective_nexus = if let Some(lifecycle) = lifecycle {
            let mut updated = nexus.clone();
            updated.lane_catalog = lifecycle.catalog_update.updated_catalog.clone();
            updated.lane_config = lifecycle.catalog_update.updated_lane_config.clone();
            updated.dataspace_catalog = lifecycle.catalog_update.updated_dataspace_catalog.clone();
            std::borrow::Cow::Owned(updated)
        } else {
            std::borrow::Cow::Borrowed(nexus)
        };
        // Preserve positions in the authenticated canonical bundle even when a
        // later validation/reset filter removes an earlier element.
        let bundle =
            iroha_data_model::da::pin_intent::DaPinIntentBundle::new(pending.intents.clone());
        let positions = State::pin_intent_bundle_positions(&bundle.intents);
        let (intents, rejected) = crate::da::sanitize_pin_intents_against_nexus_at_height(
            bundle.intents,
            &effective_nexus,
            pending.block_height,
            |account| world.accounts.get(account).is_some(),
        );
        for reason in rejected {
            warn!(
                height = pending.block_height,
                ?reason,
                "dropping invalid DA pin intent during World preparation"
            );
        }
        // Use the applying State's captured incarnation boundary. Local DA
        // cursor journals may be stale or ahead and cannot veto a World write.
        let mut records = Vec::new();
        for intent in intents {
            let reset_by_transition = lifecycle.is_some_and(|pending_lifecycle| {
                pending_lifecycle
                    .catalog_update
                    .lanes_to_reset
                    .contains(&intent.lane_id)
            });
            if reset_by_transition
                || activation_heights
                    .get(&intent.lane_id)
                    .is_some_and(|height| pending.block_height <= *height)
            {
                continue;
            }
            let ticket = intent.storage_ticket;
            let manifest = intent.manifest_hash;
            let lane_epoch = (intent.lane_id, intent.epoch, intent.sequence);
            // The sanitizer already rejects duplicate identities within this bundle.
            // Only authoritative predecessor/overlay indexes decide remaining collisions.
            if world.da_pin_intents_by_ticket.get(&ticket).is_some()
                || world.da_pin_intents_by_manifest.get(&manifest).is_some()
                || world
                    .da_pin_intents_by_lane_epoch
                    .get(&lane_epoch)
                    .is_some()
            {
                continue;
            }
            let position = positions
                .get(&intent)
                .copied()
                .ok_or("prepared DA pin lost its canonical bundle position")?;
            let index_in_bundle = crate::da::da_bundle_location_index(position)
                .ok_or("prepared DA pin bundle location exceeds its wire range")?;
            let record = DaPinIntentWithLocation {
                intent,
                location: DaCommitmentLocation {
                    block_height: pending.block_height,
                    index_in_bundle,
                },
            };
            // Locations are unique within the one canonical bundle. Existing
            // records belong to authenticated predecessor heights; replacement
            // starts from MV undo before preparing this height's bundle.
            records.push(record);
        }
        Ok(records)
    }

    fn apply_pin(world: &mut WorldBlock<'_>, record: &DaPinIntentWithLocation) {
        let intent = &record.intent;
        let ticket = intent.storage_ticket;
        if let Some(alias) = &intent.alias {
            world.da_pin_intents_by_alias.insert(alias.clone(), ticket);
        }
        world
            .da_pin_intents_by_ticket
            .insert(ticket, record.clone());
        world
            .da_pin_intents_by_manifest
            .insert(intent.manifest_hash, ticket);
        world
            .da_pin_intents_by_lane_epoch
            .insert((intent.lane_id, intent.epoch, intent.sequence), ticket);
    }
}

impl StateBlock<'_> {
    /// Project the four persisted pin indexes through the same pure admission plan as commit.
    #[cfg(test)]
    pub(crate) fn json_serialize_committed_da_pin_indexes(&self) -> [Option<String>; 4] {
        // Finalized snapshots borrow the exact already-applied tail. Recomputing this
        // plan would require an executing block and could substitute its original effects.
        if self.has_finalized_world_tail_for_snapshot() {
            return Default::default();
        }
        if self.pending_da_pin_intents.is_none() && self.pending_autoscale_lifecycle.is_none() {
            return Default::default();
        }
        let records = self
            .pending_da_pin_intents
            .as_ref()
            .map(|pending| {
                PreparedWorldCommit::prepare_pins(
                    &self.world,
                    &self.nexus,
                    &self.lane_incarnation_activation_heights,
                    pending,
                    self.pending_autoscale_lifecycle.as_ref(),
                )
                .expect("validated pin bundle must retain representable canonical locations")
            })
            .unwrap_or_default();
        let mut tickets = BTreeMap::new();
        let mut aliases = BTreeMap::new();
        let mut manifests = BTreeMap::new();
        let mut lane_epochs = BTreeMap::new();
        if let Some(lifecycle) = &self.pending_autoscale_lifecycle {
            let stale = State::da_pin_intent_index_prune_keys_for_lanes(
                &self.world.da_pin_intents_by_ticket,
                &self.world.da_pin_intents_by_alias,
                &self.world.da_pin_intents_by_manifest,
                &self.world.da_pin_intents_by_lane_epoch,
                &lifecycle.catalog_update.lanes_to_reset,
            );
            tickets.extend(stale.tickets.into_iter().map(|key| (key, None)));
            aliases.extend(stale.aliases.into_iter().map(|key| (key, None)));
            manifests.extend(stale.manifests.into_iter().map(|key| (key, None)));
            lane_epochs.extend(stale.lane_epochs.into_iter().map(|key| (key, None)));
        }
        for record in records {
            let intent = &record.intent;
            let ticket = intent.storage_ticket;
            if let Some(alias) = &intent.alias {
                aliases.insert(alias.clone(), Some(ticket));
            }
            manifests.insert(intent.manifest_hash, Some(ticket));
            lane_epochs.insert(
                (intent.lane_id, intent.epoch, intent.sequence),
                Some(ticket),
            );
            tickets.insert(ticket, Some(record));
        }
        macro_rules! project {
            ($store:ident, $changes:ident) => {{
                if $changes.is_empty() {
                    None
                } else {
                    let mut out = String::new();
                    mv::json::json_serialize_storage_block_with_changes(
                        &self.world.$store,
                        &$changes,
                        &mut out,
                    );
                    Some(out)
                }
            }};
        }
        [
            project!(da_pin_intents_by_ticket, tickets),
            project!(da_pin_intents_by_alias, aliases),
            project!(da_pin_intents_by_manifest, manifests),
            project!(da_pin_intents_by_lane_epoch, lane_epochs),
        ]
    }
}

impl State {
    /// Reconstruct the derived pin cache, preserving explicitly unbound aliases.
    pub(in crate::state) fn da_pin_cache_from_world(
        &self,
        releases: &mut view_acquisition::WorldReadReleases,
    ) -> DaPinStore {
        let by_ticket = self
            .world
            .da_pin_intents_by_ticket
            .view_retaining(&mut releases.da_pin_intents_by_ticket);
        let mut canonical: Vec<_> = by_ticket.iter().map(|(_, value)| value.clone()).collect();
        canonical
            .sort_by_key(|entry| (entry.location.block_height, entry.location.index_in_bundle));
        let mut cache = DaPinStore::from_intents(&canonical);
        let aliases = self
            .world
            .da_pin_intents_by_alias
            .view_retaining(&mut releases.da_pin_intents_by_alias);
        cache.replace_alias_bindings(
            aliases
                .iter()
                .map(|(alias, ticket)| (alias.clone(), *ticket))
                .collect(),
        );
        cache
    }

    /// Materialize a derived cache only after its authoritative World is visible.
    /// A cache collision triggers reconstruction; it can never veto a World write.
    fn publish_prepared_da_pins(
        &self,
        records: Vec<DaPinIntentWithLocation>,
        cache: &mut DaPinStore,
        releases: &mut view_acquisition::WorldReadReleases,
    ) {
        if records.is_empty() {
            return;
        }
        for record in records {
            if !cache.insert_with_location(record) {
                // Recovery from a stale/ahead cache is deliberately a cold path.
                // Ordinary publication only inserts its bounded prepared records.
                // TODO: admit cold reconstruction memory with the complete State
                // resource owner before qualifying restart/publication budgets.
                *cache = self.da_pin_cache_from_world(releases);
                break;
            }
        }
    }
}

#[cfg(test)]
#[path = "world_commit_tests.rs"]
mod tests;
