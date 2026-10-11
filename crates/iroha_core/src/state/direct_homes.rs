//! Canonical direct dataspace homes of live asset-definition incarnations.
//!
//! `world.asset_definition_direct_homes` maps an [`AssetDefinitionId`] to the immutable
//! [`AssetDefinitionDirectHomeV1`] of its live incarnation. A row exists only while that
//! incarnation is live. Native registration inserts it together with the definition, and
//! unregistration removes it together with the definition; there are no tombstones. The
//! block invariant below is the backstop that keeps every write path to these rules.

use super::*;

/// Check one direct-home row against the exact live definition incarnation it names.
///
/// Absence remains absence. A present row must be valid, name a live domainless definition
/// and carry that definition's exact live incarnation.
///
/// # Errors
/// Rejects an invalid or orphan row, a foreign incarnation, or a domain-owned definition.
pub(crate) fn direct_home_dataspace(
    row: Option<&AssetDefinitionDirectHomeV1>,
    definition: Option<&AssetDefinition>,
    incarnation: Option<&AxtAssetIncarnationV1>,
) -> Result<Option<DataSpaceId>, ParseError> {
    let Some(row) = row else {
        return Ok(None);
    };
    row.validate()?;
    let definition =
        definition.ok_or_else(|| ParseError::new("direct asset home has no live definition"))?;
    if incarnation != Some(&row.incarnation) {
        return Err(ParseError::new(
            "direct asset home differs from the live definition incarnation",
        ));
    }
    iroha_data_model::asset::AssetDefinitionHome::from_definition(
        definition,
        Some(row.dataspace_id),
    )?;
    Ok(Some(row.dataspace_id))
}

/// Check one key of the direct-home table between two exact images.
///
/// An insertion requires a newly installed incarnation, a removal requires the removed
/// incarnation to be gone, and a replacement is allowed only to a new incarnation. A row is
/// therefore immutable for the whole life of one incarnation.
///
/// # Errors
/// Rejects an insertion for a pre-existing incarnation, a removal while that incarnation is
/// still live, or a row modified in place.
pub(crate) fn validate_direct_home_transition(
    before: Option<&AssetDefinitionDirectHomeV1>,
    after: Option<&AssetDefinitionDirectHomeV1>,
    incarnation_before: Option<&AxtAssetIncarnationV1>,
    incarnation_after: Option<&AxtAssetIncarnationV1>,
) -> Result<(), ParseError> {
    let inserted_for_existing =
        |row: &AssetDefinitionDirectHomeV1| incarnation_before == Some(&row.incarnation);
    let removed_while_live =
        |row: &AssetDefinitionDirectHomeV1| incarnation_after == Some(&row.incarnation);
    match (before, after) {
        (None, None) => Ok(()),
        (Some(before), Some(after)) if before == after => Ok(()),
        (None, Some(after)) if inserted_for_existing(after) => Err(ParseError::new(
            "direct asset home cannot be added to an existing incarnation",
        )),
        (Some(before), None) if removed_while_live(before) => Err(ParseError::new(
            "direct asset home cannot be removed while its incarnation is live",
        )),
        (Some(before), Some(after))
            if before.incarnation == after.incarnation
                || removed_while_live(before)
                || inserted_for_existing(after) =>
        {
            Err(ParseError::new(
                "direct asset home is immutable for one incarnation",
            ))
        }
        _ => Ok(()),
    }
}

impl crate::smartcontracts::ValidSingularQuery
    for iroha_data_model::query::asset::FindAssetDefinitionDirectHome
{
    /// Return the exact live direct-home row. An absent definition, an absent row and a row
    /// that no longer matches its live incarnation all report the same absent definition.
    fn execute(
        &self,
        state_ro: &impl StateReadOnly,
    ) -> Result<AssetDefinitionDirectHomeV1, iroha_data_model::query::error::QueryExecutionFail>
    {
        let world = state_ro.world();
        let id = self.asset_definition_id();
        let absent = || FindError::AssetDefinition(id.clone());
        let row = world
            .asset_definition_direct_homes()
            .get(id)
            .copied()
            .ok_or_else(absent)?;
        direct_home_dataspace(
            Some(&row),
            world.asset_definitions().get(id),
            world.axt_asset_incarnations().get(id),
        )
        .map_err(|_| absent())?;
        Ok(row)
    }
}

impl StateTransaction<'_, '_> {
    /// Home a newly installed definition incarnation in its explicitly authorized dataspace.
    ///
    /// # Errors
    /// Rejects an absent definition, a pre-existing or different incarnation, an incoherent
    /// home (domain-owned definition or universal dataspace) or an existing row.
    pub(crate) fn register_direct_asset_definition_home(
        &mut self,
        id: &AssetDefinitionId,
        incarnation: AxtAssetIncarnationV1,
        dataspace_id: DataSpaceId,
    ) -> Result<(), ParseError> {
        let definition = self.world.asset_definitions.get(id).ok_or_else(|| {
            ParseError::new("direct-home registration requires its installed definition")
        })?;
        if self
            .world
            .asset_definitions
            .get_before_transaction(id)
            .is_some()
            && self.world.axt_asset_incarnations.get_before_transaction(id) == Some(&incarnation)
        {
            return Err(ParseError::new(
                "direct-home registration requires a newly installed incarnation",
            ));
        }
        iroha_data_model::asset::AssetDefinitionHome::from_definition(
            definition,
            Some(dataspace_id),
        )?;
        if self.world.axt_asset_incarnations.get(id) != Some(&incarnation) {
            return Err(ParseError::new(
                "direct-home registration requires the exact installed incarnation",
            ));
        }
        if self.world.asset_definition_direct_homes.get(id).is_some() {
            return Err(ParseError::new(
                "direct-home registration cannot replace an existing home",
            ));
        }
        let row = AssetDefinitionDirectHomeV1 {
            incarnation,
            dataspace_id,
        };
        row.validate()?;
        self.world
            .asset_definition_direct_homes
            .insert(id.clone(), row);
        Ok(())
    }

    /// Remove the direct home of the exact live incarnation that is being unregistered.
    ///
    /// # Errors
    /// Rejects a row whose definition or incarnation is no longer the live one.
    pub(crate) fn retire_direct_asset_definition_home(
        &mut self,
        id: &AssetDefinitionId,
    ) -> Result<(), ParseError> {
        let Some(row) = self.world.asset_definition_direct_homes.get(id).copied() else {
            return Ok(());
        };
        if self.world.asset_definitions.get(id).is_none()
            || self.world.axt_asset_incarnations.get(id) != Some(&row.incarnation)
        {
            return Err(ParseError::new(
                "direct-home retirement requires its exact live incarnation",
            ));
        }
        self.world.asset_definition_direct_homes.remove(id.clone());
        Ok(())
    }
}

impl StateBlock<'_> {
    /// Check every direct-home, definition and incarnation key this block changed.
    ///
    /// Untouched keys were checked by the block that last changed them, so only the changed
    /// keys need the transition and row checks. Every live direct-homed definition keeps its
    /// row because a row may only disappear together with its incarnation.
    pub(super) fn validate_direct_home_rows(&self) -> Result<(), ParseError> {
        let mut keys = BTreeSet::new();
        keys.extend(
            self.world
                .asset_definition_direct_homes
                .touched_entries()
                .map(|entry| entry.key.clone()),
        );
        keys.extend(
            self.world
                .asset_definitions
                .touched_entries()
                .map(|entry| entry.key.clone()),
        );
        keys.extend(
            self.world
                .axt_asset_incarnations
                .touched_entries()
                .map(|entry| entry.key.clone()),
        );
        for id in &keys {
            let incarnation_after = self.world.axt_asset_incarnations.get(id);
            validate_direct_home_transition(
                self.world
                    .asset_definition_direct_homes
                    .get_before_block(id),
                self.world.asset_definition_direct_homes.get(id),
                self.world.axt_asset_incarnations.get_before_block(id),
                incarnation_after,
            )?;
            let home = direct_home_dataspace(
                self.world.asset_definition_direct_homes.get(id),
                self.world.asset_definitions.get(id),
                incarnation_after,
            )?;
            if let Some(definition) = self.world.asset_definitions.get(id) {
                iroha_data_model::asset::AssetDefinitionHome::validate_definition(
                    definition, home,
                )?;
            }
        }
        Ok(())
    }
}

/// Refuse a lane catalog update that changes the class of a dataspace that already had lanes.
///
/// Retiring every lane of a dataspace is not a class change; re-adding lanes later is checked
/// against [`ensure_homed_dataspaces_keep_lanes`], which keeps homing dataspaces populated.
pub(super) fn ensure_dataspace_classes_preserved(
    previous: &LaneCatalog,
    updated: &LaneCatalog,
) -> Result<(), LaneLifecycleError> {
    for lane in updated.lanes() {
        if previous
            .dataspace_visibility(lane.dataspace_id)
            .is_some_and(|visibility| visibility != lane.visibility)
        {
            return Err(LaneLifecycleError::DataspaceVisibilityChanged {
                dataspace_id: lane.dataspace_id,
            });
        }
    }
    Ok(())
}

/// Refuse a lane catalog that leaves a dataspace homing live asset definitions without lanes.
///
/// A dataspace without lanes has no class, so a later addition could flip it. Keeping at least
/// one lane for every home pins the class of every dataspace that owns a definition.
pub(super) fn ensure_homed_dataspaces_keep_lanes(
    world: &(impl WorldReadOnly + ?Sized),
    updated: &LaneCatalog,
) -> Result<(), LaneLifecycleError> {
    for (asset_definition_id, definition) in world.asset_definitions().iter() {
        let Ok(Some(dataspace_id)) = crate::read_scope::home_dataspace(world, definition) else {
            continue;
        };
        if dataspace_id != DataSpaceId::UNIVERSAL
            && updated.dataspace_visibility(dataspace_id).is_none()
        {
            return Err(LaneLifecycleError::HomedDataspaceWithoutLanes {
                dataspace_id,
                asset_definition_id: asset_definition_id.clone(),
            });
        }
    }
    Ok(())
}

#[cfg(any(test, feature = "iroha-core-tests"))]
impl World {
    /// Atomically seed a direct-dataspace definition and exact balances in an owned test world.
    ///
    /// This fixture does not authorize production registration. The instruction executor
    /// remains responsible for SNS ownership, route and visibility checks. The fixture seeds the
    /// supplied balance buckets exactly; read-path tests may use buckets that home confinement
    /// would refuse during execution.
    ///
    /// # Errors
    /// Rejects invalid or duplicate homes/definitions/aliases, a balance scope that does not
    /// match the definition's policy, missing balance accounts, invalid quantities and supply
    /// overflow without publishing any part of the fixture.
    pub fn insert_direct_asset_definition_with_assets_for_testing(
        &mut self,
        mut definition: AssetDefinition,
        dataspace_id: DataSpaceId,
        assets: impl IntoIterator<Item = Asset>,
    ) -> Result<(), Error> {
        use iroha_data_model::asset::AssetDefinitionHome;
        let fixture_error = |error: ParseError| Error::InvariantViolation(error.to_string().into());
        let id = definition.id().clone();
        AssetDefinitionHome::from_definition(&definition, Some(dataspace_id))
            .map_err(fixture_error)?;
        if self.asset_definitions.view().get(&id).is_some()
            || self.asset_definition_direct_homes.view().get(&id).is_some()
        {
            return Err(Error::InvariantViolation(
                "direct-home fixture cannot replace an existing definition or home".into(),
            ));
        }
        let incarnation =
            AxtAssetIncarnationV1::try_from_bytes(*Hash::new(id.aid_bytes()).as_ref())
                .map_err(|error| Error::InvariantViolation(error.to_string().into()))?;
        let row = AssetDefinitionDirectHomeV1 {
            incarnation,
            dataspace_id,
        };
        row.validate().map_err(fixture_error)?;
        let alias = definition.alias.take();
        if let Some(alias) = alias.as_ref()
            && let Some(domain) = alias.domain_segment()
        {
            let domain_id =
                DomainId::try_new(domain, alias.dataspace_segment()).map_err(fixture_error)?;
            if self.domains.view().get(&domain_id).is_none() {
                return Err(Error::InvariantViolation(
                    format!("fixture alias `{alias}` references missing domain {domain_id}").into(),
                ));
            }
        }
        definition.total_quantity = Quantity::zero();
        let policy = definition.balance_scope_policy();
        // Match the ordinary constructor's last supplied balance per exact asset identity.
        let balances: BTreeMap<_, _> = assets
            .into_iter()
            .map(IntoKeyValue::into_key_value)
            .collect();
        let mut block = self.block();
        {
            let mut transaction = block.transaction_without_telemetry(LaneConfig::default(), 0);
            transaction.insert_asset_definition_entry(id.clone(), definition);
            transaction
                .axt_asset_incarnations
                .insert(id.clone(), incarnation);
            transaction
                .asset_definition_direct_homes
                .insert(id.clone(), row);
            if let Some(alias) = alias {
                transaction.bind_asset_definition_alias(&id, alias, None, None, 0)?;
            }
            for (asset_id, value) in balances {
                let scope_matches_policy = matches!(
                    (policy, asset_id.scope()),
                    (AssetBalancePolicy::Global, AssetBalanceScope::Global)
                        | (
                            AssetBalancePolicy::DataspaceRestricted,
                            AssetBalanceScope::Dataspace(_)
                        )
                );
                if asset_id.definition() != &id || !scope_matches_policy {
                    return Err(Error::InvariantViolation(
                        "direct-home fixture requires its exact original balance identity".into(),
                    ));
                }
                transaction.asset_or_insert_exact(&asset_id, value.as_ref().clone())?;
                transaction.increase_asset_total_amount(&id, value.as_ref())?;
            }
            if transaction.execution_deferral.borrow().is_some() {
                return Err(Error::InvariantViolation(
                    "direct-home fixture execution was locally deferred".into(),
                ));
            }
            transaction.apply();
        }
        block.commit();
        Ok(())
    }

    /// Install a direct home for an existing domainless definition in an owned test world.
    ///
    /// # Errors
    /// Rejects an absent definition, an incoherent home or an existing row.
    pub fn set_asset_definition_dataspace_for_testing(
        &mut self,
        id: AssetDefinitionId,
        dataspace_id: DataSpaceId,
    ) -> Result<(), ParseError> {
        use iroha_data_model::asset::AssetDefinitionHome;
        let definitions = self.asset_definitions.view();
        let definition = definitions.get(&id).ok_or_else(|| {
            ParseError::new("direct-home fixture requires an existing definition")
        })?;
        AssetDefinitionHome::from_definition(definition, Some(dataspace_id))?;
        drop(definitions);
        if self.asset_definition_direct_homes.view().get(&id).is_some() {
            return Err(ParseError::new(
                "direct-home fixture cannot replace an existing home",
            ));
        }
        let incarnation = self
            .axt_asset_incarnations
            .view()
            .get(&id)
            .copied()
            .unwrap_or_else(|| {
                AxtAssetIncarnationV1::try_from_bytes(*Hash::new(id.aid_bytes()).as_ref())
                    .expect("fixture hash is a valid nonzero incarnation")
            });
        let row = AssetDefinitionDirectHomeV1 {
            incarnation,
            dataspace_id,
        };
        row.validate()?;
        let mut block = self.block();
        {
            let mut transaction = block.transaction_without_telemetry(LaneConfig::default(), 0);
            transaction
                .axt_asset_incarnations
                .insert(id.clone(), incarnation);
            transaction.asset_definition_direct_homes.insert(id, row);
            transaction.apply();
        }
        block.commit();
        Ok(())
    }
}

#[cfg(test)]
#[path = "direct_home_tests.rs"]
mod direct_home_tests;
