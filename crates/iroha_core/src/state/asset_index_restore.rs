//! Restore asset lookup indexes from the same two authoritative MV images.
//!
//! Domain context comes from the definition in the selected image. Both images
//! are checked before replacing any index; the canonical sources are never
//! mutated while reconstructing their derived replacement history.
//! TODO: admit these restore allocations through the original snapshot resource
//! owner along with the remaining infallible derived-index reconstruction.

use super::*;
use mv::storage::History;

#[expect(
    clippy::zero_sized_map_values,
    reason = "MV snapshot restoration requires complete current and undo key/value maps"
)]
#[derive(Default)]
struct Image {
    domains: BTreeMap<AssetDefinitionId, DomainId>,
    domain_definitions: BTreeMap<(DomainId, AssetDefinitionId), ()>,
    owners: BTreeMap<(AccountId, AssetDefinitionId), ()>,
    holders: BTreeMap<(AssetDefinitionId, AccountId), ()>,
    asset_counts: BTreeMap<AssetDefinitionId, u64>,
    definition_assets: BTreeMap<(AssetDefinitionId, AssetId), ()>,
    domain_assets: BTreeMap<(DomainId, AssetId), ()>,
    nonzero_holders: BTreeMap<(AssetDefinitionId, AccountId), ()>,
}

fn project<'a>(
    definitions: impl Iterator<Item = (&'a AssetDefinitionId, &'a AssetDefinition)>,
    assets: impl Iterator<Item = (&'a AssetId, &'a AssetValue)>,
    domain_exists: impl Fn(&DomainId) -> bool,
    definition_exists: impl Fn(&AssetDefinitionId) -> bool,
    home: impl Fn(&AssetDefinitionId) -> Option<AssetDefinitionDirectHomeV1>,
    incarnation: impl Fn(&AssetDefinitionId) -> Option<AxtAssetIncarnationV1>,
) -> Result<Image, String> {
    let mut image = Image::default();
    for (id, definition) in definitions {
        let domain = definition.owning_domain().as_ref();
        let incarnation = incarnation(id);
        let direct =
            direct_home_dataspace(home(id).as_ref(), Some(definition), incarnation.as_ref())
                .map_err(|error| error.to_string())?;
        iroha_data_model::asset::AssetDefinitionHome::from_definition(definition, direct)
            .map_err(|error| error.to_string())?;
        if let Some(domain) = domain {
            if !domain_exists(domain) {
                return Err(format!(
                    "asset definition {id} references missing owning domain {domain}"
                ));
            }
            image.domains.insert(id.clone(), domain.clone());
            image
                .domain_definitions
                .insert((domain.clone(), id.clone()), ());
        }
        image
            .owners
            .insert((definition.owned_by().clone(), id.clone()), ());
    }
    for (id, value) in assets {
        if !definition_exists(id.definition()) {
            return Err(format!(
                "asset {id} references missing asset definition {}",
                id.definition()
            ));
        }
        image
            .holders
            .insert((id.definition().clone(), id.account().clone()), ());
        image
            .definition_assets
            .insert((id.definition().clone(), id.clone()), ());
        *image
            .asset_counts
            .entry(id.definition().clone())
            .or_default() += 1;
        if let Some(domain) = image.domains.get(id.definition()) {
            image.domain_assets.insert((domain.clone(), id.clone()), ());
        }
        if !value.as_ref().is_zero() {
            image
                .nonzero_holders
                .insert((id.definition().clone(), id.account().clone()), ());
        }
    }
    Ok(image)
}

#[derive(Default)]
struct Touches {
    definitions: BTreeSet<AssetDefinitionId>,
    domains: BTreeSet<(DomainId, AssetDefinitionId)>,
    owners: BTreeSet<(AccountId, AssetDefinitionId)>,
    holders: BTreeSet<(AssetDefinitionId, AccountId)>,
    definition_assets: BTreeSet<(AssetDefinitionId, AssetId)>,
    asset_definitions: BTreeSet<AssetDefinitionId>,
    asset_domains: BTreeSet<(DomainId, AssetId)>,
}

impl Touches {
    fn sources(
        definitions: &History<'_, AssetDefinitionId, AssetDefinition>,
        assets: &History<'_, AssetId, AssetValue>,
    ) -> Self {
        let mut touched = Self::default();
        for (id, prior) in definitions.revert_map().iter() {
            touched.definitions.insert(id.clone());
            for definition in [prior.as_ref(), definitions.current().get(id)]
                .into_iter()
                .flatten()
            {
                touched
                    .owners
                    .insert((definition.owned_by().clone(), id.clone()));
                if let Some(domain) = definition.owning_domain() {
                    touched.domains.insert((domain.clone(), id.clone()));
                }
            }
        }
        for (id, _) in assets.revert_map().iter() {
            touched.asset_definitions.insert(id.definition().clone());
            touched
                .holders
                .insert((id.definition().clone(), id.account().clone()));
            touched
                .definition_assets
                .insert((id.definition().clone(), id.clone()));
            for definition in [
                definitions.current().get(id.definition()),
                definitions.get_before_block(id.definition()),
            ]
            .into_iter()
            .flatten()
            {
                if let Some(domain) = definition.owning_domain() {
                    touched.asset_domains.insert((domain.clone(), id.clone()));
                }
            }
        }
        touched
    }
}

/// Keep changed rows and redundant source touches with their prior value.
fn restore<K: mv::Key, V: mv::Value + PartialEq>(
    current: BTreeMap<K, V>,
    mut previous: BTreeMap<K, V>,
    touched: &BTreeSet<K>,
) -> Storage<K, V> {
    let mut keys = touched.clone();
    for key in current.keys().chain(previous.keys()) {
        if current.get(key) != previous.get(key) {
            keys.insert(key.clone());
        }
    }
    let undo = keys
        .into_iter()
        .map(|key| {
            let prior = previous.remove(&key);
            (key, prior)
        })
        .collect();
    Storage::from_snapshot_parts(current, undo)
}

/// Check both source images before replacing membership rows and asset counters.
pub(super) fn assets(world: &mut World) -> Result<(), String> {
    // Borrow the backing once so all three histories retain disjoint source fields.
    let world: &mut WorldData = world;
    let definitions = world.asset_definitions.history();
    let domains = world.domains.history();
    let balances = world.assets.history();
    let incarnations = world.axt_asset_incarnations.history();
    let homes = world.asset_definition_direct_homes.history();
    // A row is immutable for one incarnation and disappears only with that incarnation.
    for (id, before) in homes.revert_map().iter() {
        validate_direct_home_transition(
            before.as_ref(),
            homes.current().get(id),
            incarnations.get_before_block(id),
            incarnations.current().get(id),
        )
        .map_err(|error| format!("snapshot direct home of {id}: {error}"))?;
    }
    // Check every row in both images, including orphans absent from the definition iterator.
    for (id, row) in homes.current().iter() {
        direct_home_dataspace(
            Some(row),
            definitions.current().get(id),
            incarnations.current().get(id),
        )
        .map_err(|error| format!("snapshot direct home of {id}: {error}"))?;
    }
    for (id, row) in homes.iter_before_block() {
        direct_home_dataspace(
            Some(row),
            definitions.get_before_block(id),
            incarnations.get_before_block(id),
        )
        .map_err(|error| format!("snapshot predecessor direct home of {id}: {error}"))?;
    }
    let current = project(
        definitions.current().iter(),
        balances.current().iter(),
        |id| domains.current().get(id).is_some(),
        |id| definitions.current().get(id).is_some(),
        |id| homes.current().get(id).copied(),
        |id| incarnations.current().get(id).copied(),
    )?;
    let previous = project(
        definitions.iter_before_block(),
        balances.iter_before_block(),
        |id| domains.get_before_block(id).is_some(),
        |id| definitions.get_before_block(id).is_some(),
        |id| homes.get_before_block(id).copied(),
        |id| incarnations.get_before_block(id).copied(),
    )?;
    let touched = Touches::sources(&definitions, &balances);
    drop((definitions, domains, balances));
    world.asset_definition_domains =
        restore(current.domains, previous.domains, &touched.definitions);
    world.domain_asset_definitions = restore(
        current.domain_definitions,
        previous.domain_definitions,
        &touched.domains,
    );
    world.asset_definitions_by_owner = restore(current.owners, previous.owners, &touched.owners);
    world.asset_definition_holders = restore(current.holders, previous.holders, &touched.holders);
    world.asset_definition_asset_counts = restore(
        current.asset_counts,
        previous.asset_counts,
        &touched.asset_definitions,
    );
    world.asset_definition_assets = restore(
        current.definition_assets,
        previous.definition_assets,
        &touched.definition_assets,
    );
    world.assets_by_domain = restore(
        current.domain_assets,
        previous.domain_assets,
        &touched.asset_domains,
    );
    world.asset_definition_nonzero_holders = restore(
        current.nonzero_holders,
        previous.nonzero_holders,
        &touched.holders,
    );
    Ok(())
}

#[cfg(test)]
mod tests;
