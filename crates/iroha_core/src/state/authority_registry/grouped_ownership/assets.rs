//! Exact balance partitions, four derived membership indexes and asset counts.
//!
//! Holder membership is existential over the canonical account/definition
//! partitions across the complete original images. A zero partition never removes another nonzero partition.

use super::asset_definitions::{
    AssetDefinitionWork, prepay_asset_definition_id, validate_original_direct_home_rows,
    validate_original_direct_home_transitions,
};
use super::*;
use crate::state::authority_registry::{
    borrowed_controller_work::prepay_account_id, original_images::RawStorageImages,
};
use iroha_data_model::nexus::AxtAssetIncarnationV1;
use iroha_data_model::{
    asset::{
        AssetBalancePolicy, AssetBalanceScope, AssetDefinition, AssetDefinitionDirectHomeV1,
        AssetDefinitionId, AssetId, AssetValue,
    },
    domain::Domain,
};

/// Retained balance, definition, domain and derived readers from one native cut.
pub(in super::super) struct CheckedAssets<'world> {
    world: &'world World,
    homes: CommittedStorageView<'world, AssetDefinitionId, AssetDefinitionDirectHomeV1>,
    incarnations: CommittedStorageView<'world, AssetDefinitionId, AxtAssetIncarnationV1>,
    rows: CommittedStorageView<'world, AssetId, AssetValue>,
    definitions: CommittedStorageView<'world, AssetDefinitionId, AssetDefinition>,
    domains: CommittedStorageView<'world, DomainId, Domain>,
    by_definition: CommittedStorageView<'world, (AssetDefinitionId, AssetId), ()>,
    by_domain: CommittedStorageView<'world, (DomainId, AssetId), ()>,
    holders: CommittedStorageView<'world, (AssetDefinitionId, AccountId), ()>,
    nonzero: CommittedStorageView<'world, (AssetDefinitionId, AccountId), ()>,
    asset_counts: CommittedStorageView<'world, AssetDefinitionId, u64>,
}

impl<'world> CheckedAssets<'world> {
    /// Check both original images with bounded prepaid work and no row repair.
    pub(in super::super) fn capture(
        world: &'world World,
        max_work: u64,
    ) -> Result<Self, GroupedOwnershipError> {
        let checked = Self {
            world,
            homes: world
                .asset_definition_direct_homes
                .try_committed_view_nonblocking()?,
            incarnations: world
                .axt_asset_incarnations
                .try_committed_view_nonblocking()?,
            rows: world.assets.try_committed_view_nonblocking()?,
            definitions: world.asset_definitions.try_committed_view_nonblocking()?,
            domains: world.domains.try_committed_view_nonblocking()?,
            by_definition: world
                .asset_definition_assets
                .try_committed_view_nonblocking()?,
            by_domain: world.assets_by_domain.try_committed_view_nonblocking()?,
            holders: world
                .asset_definition_holders
                .try_committed_view_nonblocking()?,
            nonzero: world
                .asset_definition_nonzero_holders
                .try_committed_view_nonblocking()?,
            asset_counts: world
                .asset_definition_asset_counts
                .try_committed_view_nonblocking()?,
        };
        let result = validate_original_assets(
            &checked.rows,
            &checked.definitions,
            &checked.domains,
            &checked.by_definition,
            &checked.by_domain,
            &checked.holders,
            &checked.nonzero,
            &checked.asset_counts,
            &checked.homes,
            &checked.incarnations,
            max_work,
        );
        checked.finish_validation(result)
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

    /// Borrow precisely the rows validated against every original source.
    pub(in super::super) fn rows(&self) -> &CommittedStorageView<'world, AssetId, AssetValue> {
        &self.rows
    }
    /// Probe every original owner before propagating the first native refusal.
    pub(in super::super) fn matches_current(&self) -> Result<bool, GroupedOwnershipError> {
        let rows = self.rows.try_matches_current(&self.world.assets);
        let definitions = self
            .definitions
            .try_matches_current(&self.world.asset_definitions);
        let domains = self.domains.try_matches_current(&self.world.domains);
        let by_definition = self
            .by_definition
            .try_matches_current(&self.world.asset_definition_assets);
        let by_domain = self
            .by_domain
            .try_matches_current(&self.world.assets_by_domain);
        let holders = self
            .holders
            .try_matches_current(&self.world.asset_definition_holders);
        let nonzero = self
            .nonzero
            .try_matches_current(&self.world.asset_definition_nonzero_holders);
        let asset_counts = self
            .asset_counts
            .try_matches_current(&self.world.asset_definition_asset_counts);
        let homes = self
            .homes
            .try_matches_current(&self.world.asset_definition_direct_homes);
        let incarnations = self
            .incarnations
            .try_matches_current(&self.world.axt_asset_incarnations);
        let homes = homes?;
        let incarnations = incarnations?;
        let rows = rows?;
        let definitions = definitions?;
        let domains = domains?;
        let by_definition = by_definition?;
        let by_domain = by_domain?;
        let holders = holders?;
        let nonzero = nonzero?;
        let asset_counts = asset_counts?;
        Ok(homes
            && incarnations
            && rows
            && definitions
            && domains
            && by_definition
            && by_domain
            && holders
            && nonzero
            && asset_counts)
    }
}

/// One Global/Single Ed25519/domain126 row and its four singleton indexes and one count over
/// both images. This local scheduling reference is not a validity/gas/row limit.
pub(in crate::state) const ASSET_BALANCE_WORK_PER_ROW: u64 = 3566;

struct AssetBalanceWork(u64);
impl AssetBalanceWork {
    fn bounded(max_work: u64) -> Self {
        Self(max_work)
    }
    fn prepay(&mut self, amount: usize) -> Result<(), GroupedOwnershipError> {
        let amount = u64::try_from(amount).map_err(|_| GroupedOwnershipError::WorkLimit)?;
        self.0 = self
            .0
            .checked_sub(amount)
            .ok_or(GroupedOwnershipError::WorkLimit)?;
        Ok(())
    }
}
trait BalanceKey: mv::Key {
    fn prepay(&self, work: &mut AssetBalanceWork) -> Result<(), GroupedOwnershipError>;
}
impl<G: BalanceKey, K: BalanceKey> BalanceKey for (G, K) {
    fn prepay(&self, work: &mut AssetBalanceWork) -> Result<(), GroupedOwnershipError> {
        self.0.prepay(work)?;
        self.1.prepay(work)
    }
}
impl BalanceKey for AssetDefinitionId {
    fn prepay(&self, work: &mut AssetBalanceWork) -> Result<(), GroupedOwnershipError> {
        prepay_asset_definition_id(self, |amount| work.prepay(amount))
    }
}
impl BalanceKey for AccountId {
    fn prepay(&self, work: &mut AssetBalanceWork) -> Result<(), GroupedOwnershipError> {
        prepay_account_id(self, |amount| work.prepay(amount))
    }
}
impl BalanceKey for DomainId {
    fn prepay(&self, work: &mut AssetBalanceWork) -> Result<(), GroupedOwnershipError> {
        work.prepay(self.name().as_ref().len())?;
        work.prepay(self.dataspace().as_ref().len())
    }
}
impl BalanceKey for AssetId {
    fn prepay(&self, work: &mut AssetBalanceWork) -> Result<(), GroupedOwnershipError> {
        self.account().prepay(work)?;
        self.definition().prepay(work)?;
        work.prepay(1)?;
        if let AssetBalanceScope::Dataspace(_) = self.scope() {
            work.prepay(8)?;
        }
        Ok(())
    }
}
fn equal<K: BalanceKey>(
    left: &K,
    right: &K,
    work: &mut AssetBalanceWork,
) -> Result<bool, GroupedOwnershipError> {
    left.prepay(work)?;
    right.prepay(work)?;
    Ok(left == right)
}
fn next_physical<I: ExactSizeIterator>(
    rows: &mut I,
    work: &mut AssetBalanceWork,
) -> Result<Option<I::Item>, GroupedOwnershipError> {
    if rows.len() == 0 {
        return Ok(None);
    }
    work.prepay(1)?;
    Ok(rows.next())
}
fn visit_original<'a, K: BalanceKey, V: mv::Value>(
    rows: &'a impl RawStorageImages<K, V>,
    image: GroupImage,
    work: &mut AssetBalanceWork,
    mut inspect: impl FnMut(&'a K, &'a V, &mut AssetBalanceWork) -> Result<(), GroupedOwnershipError>,
) -> Result<(), GroupedOwnershipError> {
    let mut current = rows.current_entries();
    while let Some((key, value)) = next_physical(&mut current, work)? {
        let mut masked = false;
        if image == GroupImage::Predecessor {
            let mut undo = rows.undo_entries();
            while let Some((prior, _)) = next_physical(&mut undo, work)? {
                masked |= equal(key, prior, work)?;
            }
        }
        if !masked {
            inspect(key, value, work)?;
        }
    }
    if image == GroupImage::Predecessor {
        let mut undo = rows.undo_entries();
        while let Some((key, prior)) = next_physical(&mut undo, work)? {
            work.prepay(1)?;
            if let Some(value) = prior {
                inspect(key, value, work)?;
            }
        }
    }
    Ok(())
}
fn lookup<'a, K: BalanceKey, V: mv::Value>(
    rows: &'a impl RawStorageImages<K, V>,
    image: GroupImage,
    key: &K,
    work: &mut AssetBalanceWork,
) -> Result<Option<&'a V>, GroupedOwnershipError> {
    let mut found = None;
    visit_original(rows, image, work, |candidate, value, work| {
        if equal(key, candidate, work)? {
            found = Some(value);
        }
        Ok(())
    })?;
    Ok(found)
}
fn contains<G: BalanceKey, K: BalanceKey>(
    groups: &impl RawStorageImages<(G, K), ()>,
    image: GroupImage,
    group: &G,
    member: &K,
    work: &mut AssetBalanceWork,
) -> Result<bool, GroupedOwnershipError> {
    let mut found = false;
    visit_original(
        groups,
        image,
        work,
        |(candidate_group, candidate_member), (), work| {
            let group_matches = equal(group, candidate_group, work)?;
            let member_matches = equal(member, candidate_member, work)?;
            found |= group_matches && member_matches;
            Ok(())
        },
    )?;
    Ok(found)
}

fn require_member<G: BalanceKey, K: BalanceKey>(
    groups: &impl RawStorageImages<(G, K), ()>,
    image: GroupImage,
    group: &G,
    member: &K,
    index: &'static str,
    work: &mut AssetBalanceWork,
) -> Result<(), GroupedOwnershipError> {
    if contains(groups, image, group, member, work)? {
        return Ok(());
    }
    Err(GroupedOwnershipError::Corrupt {
        index,
        image,
        mismatch: GroupMismatch::MissingMember,
    })
}
fn foreign(index: &'static str, image: GroupImage) -> GroupedOwnershipError {
    GroupedOwnershipError::Corrupt {
        index,
        image,
        mismatch: GroupMismatch::ForeignMember,
    }
}
fn validate_asset_group<G: BalanceKey>(
    rows: &impl RawStorageImages<AssetId, AssetValue>,
    groups: &impl RawStorageImages<(G, AssetId), ()>,
    index: &'static str,
    projection: impl Fn(&AssetId) -> &G,
    work: &mut AssetBalanceWork,
) -> Result<(), GroupedOwnershipError> {
    for image in [GroupImage::Current, GroupImage::Predecessor] {
        visit_original(rows, image, work, |id, _, work| {
            require_member(groups, image, projection(id), id, index, work)
        })?;
        visit_original(groups, image, work, |(group, id), (), work| {
            if lookup(rows, image, id, work)?.is_none() || !equal(projection(id), group, work)? {
                return Err(foreign(index, image));
            }
            Ok(())
        })?;
    }
    Ok(())
}
fn has_partition(
    rows: &impl RawStorageImages<AssetId, AssetValue>,
    image: GroupImage,
    account: &AccountId,
    definition: &AssetDefinitionId,
    nonzero: bool,
    work: &mut AssetBalanceWork,
) -> Result<bool, GroupedOwnershipError> {
    let mut found = false;
    visit_original(rows, image, work, |id, value, work| {
        // Both complete operands are funded even when the account differs.
        let account_matches = equal(id.account(), account, work)?;
        let definition_matches = equal(id.definition(), definition, work)?;
        if account_matches && definition_matches {
            if nonzero {
                work.prepay(1)?;
                found |= !value.as_ref().is_zero();
            } else {
                found = true;
            }
        }
        Ok(())
    })?;
    Ok(found)
}
fn validate_holder_group(
    rows: &impl RawStorageImages<AssetId, AssetValue>,
    groups: &impl RawStorageImages<(AssetDefinitionId, AccountId), ()>,
    image: GroupImage,
    require_nonzero: bool,
    index: &'static str,
    work: &mut AssetBalanceWork,
) -> Result<(), GroupedOwnershipError> {
    visit_original(groups, image, work, |(definition, account), (), work| {
        if !has_partition(rows, image, account, definition, require_nonzero, work)? {
            return Err(foreign(index, image));
        }
        Ok(())
    })
}
/// Match every stored count against the original membership rows in both images.
fn validate_asset_counts(
    members: &impl RawStorageImages<(AssetDefinitionId, AssetId), ()>,
    counts: &impl RawStorageImages<AssetDefinitionId, u64>,
    image: GroupImage,
    index: &'static str,
    work: &mut AssetBalanceWork,
) -> Result<(), GroupedOwnershipError> {
    visit_original(members, image, work, |(definition, _), (), work| {
        if lookup(counts, image, definition, work)?.is_none() {
            return Err(GroupedOwnershipError::Corrupt {
                index,
                image,
                mismatch: GroupMismatch::MissingMember,
            });
        }
        Ok(())
    })?;
    visit_original(counts, image, work, |definition, count, work| {
        let mut expected = 0_u64;
        visit_original(members, image, work, |(candidate, _), (), work| {
            if equal(candidate, definition, work)? {
                expected = expected
                    .checked_add(1)
                    .ok_or(GroupedOwnershipError::WorkLimit)?;
            }
            Ok(())
        })?;
        work.prepay(1)?;
        if expected == 0 || *count != expected {
            return Err(foreign(index, image));
        }
        Ok(())
    })
}

/// The sole balance/reference/index/count relation over sealed original images.
/// Retain original phased precedence and every semantic source/index predicate.
/// No account, embedded definition ID, quantity, permission or scope rule is added.
pub(in crate::state) fn validate_original_assets(
    rows: &impl RawStorageImages<AssetId, AssetValue>,
    definitions: &impl RawStorageImages<AssetDefinitionId, AssetDefinition>,
    domains: &impl RawStorageImages<DomainId, Domain>,
    by_definition: &impl RawStorageImages<(AssetDefinitionId, AssetId), ()>,
    by_domain: &impl RawStorageImages<(DomainId, AssetId), ()>,
    holders: &impl RawStorageImages<(AssetDefinitionId, AccountId), ()>,
    nonzero: &impl RawStorageImages<(AssetDefinitionId, AccountId), ()>,
    asset_counts: &impl RawStorageImages<AssetDefinitionId, u64>,
    homes: &impl RawStorageImages<AssetDefinitionId, AssetDefinitionDirectHomeV1>,
    incarnations: &impl RawStorageImages<AssetDefinitionId, AxtAssetIncarnationV1>,
    max_work: u64,
) -> Result<(), GroupedOwnershipError> {
    let mut work = AssetBalanceWork::bounded(max_work);
    validate_asset_group(
        rows,
        by_definition,
        "world.asset_definition_assets",
        AssetId::definition,
        &mut work,
    )?;
    {
        // The shared direct-home relations meter their own prepaid work from this budget.
        let mut home_work = AssetDefinitionWork::bounded(work.0);
        validate_original_direct_home_transitions(homes, incarnations, &mut home_work)?;
        for image in [GroupImage::Current, GroupImage::Predecessor] {
            validate_original_direct_home_rows(
                homes,
                definitions,
                incarnations,
                image,
                &mut home_work,
            )?;
        }
        work.0 = home_work.remaining();
    }
    for image in [GroupImage::Current, GroupImage::Predecessor] {
        visit_original(rows, image, &mut work, |id, value, work| {
            let definition = lookup(definitions, image, id.definition(), work)?.ok_or(
                GroupedOwnershipError::Source {
                    table: "world.assets",
                    image,
                    reason: "asset definition is absent",
                },
            )?;
            work.prepay(1)?;
            if definition.balance_scope_policy() == AssetBalancePolicy::DataspaceRestricted {
                work.prepay(1)?;
                if definition.owning_domain().is_none()
                    && lookup(homes, image, id.definition(), work)?.is_none()
                {
                    return Err(GroupedOwnershipError::Source {
                        table: "world.asset_definitions",
                        image,
                        reason: "restricted definition has no owning domain",
                    });
                }
            }
            work.prepay(1)?;
            if let Some(domain) = definition.owning_domain() {
                if lookup(domains, image, domain, work)?.is_none() {
                    return Err(GroupedOwnershipError::Source {
                        table: "world.asset_definitions",
                        image,
                        reason: "owning domain is absent",
                    });
                }
                require_member(by_domain, image, domain, id, "world.assets_by_domain", work)?;
            }
            require_member(
                holders,
                image,
                id.definition(),
                id.account(),
                "world.asset_definition_holders",
                work,
            )?;
            work.prepay(1)?;
            if !value.as_ref().is_zero() {
                require_member(
                    nonzero,
                    image,
                    id.definition(),
                    id.account(),
                    "world.asset_definition_nonzero_holders",
                    work,
                )?;
            }
            Ok(())
        })?;
        visit_original(by_domain, image, &mut work, |(domain, id), (), work| {
            if lookup(rows, image, id, work)?.is_none() {
                return Err(foreign("world.assets_by_domain", image));
            }
            let Some(definition) = lookup(definitions, image, id.definition(), work)? else {
                return Err(foreign("world.assets_by_domain", image));
            };
            work.prepay(1)?;
            let matching = match definition.owning_domain() {
                Some(actual) => equal(actual, domain, work)?,
                None => false,
            };
            if !matching {
                return Err(foreign("world.assets_by_domain", image));
            }
            Ok(())
        })?;
        validate_holder_group(
            rows,
            holders,
            image,
            false,
            "world.asset_definition_holders",
            &mut work,
        )?;
        validate_holder_group(
            rows,
            nonzero,
            image,
            true,
            "world.asset_definition_nonzero_holders",
            &mut work,
        )?;
        validate_asset_counts(
            by_definition,
            asset_counts,
            image,
            "world.asset_definition_asset_counts",
            &mut work,
        )?;
    }
    Ok(())
}

#[cfg(test)]
pub(in crate::state) mod test_support;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod work_tests;

#[cfg(test)]
mod direct_home_balance_tests {
    use super::*;
    use iroha_model_base::topology::DataSpaceId;

    #[test]
    fn direct_home_balances_retain_and_check_their_authority_owners() {
        let mut world = test_support::fixture(false);
        let id = test_support::definition("coin");
        world
            .set_asset_definition_dataspace_for_testing(id.clone(), DataSpaceId::new(7))
            .unwrap();
        assert!(CheckedAssets::capture(&world, 16_777_216).is_ok());
        world.axt_asset_incarnations.insert(
            id,
            AxtAssetIncarnationV1::try_from_bytes(iroha_crypto::Hash::new([99]).into()).unwrap(),
        );
        assert!(matches!(
            CheckedAssets::capture(&world, 16_777_216),
            Err(GroupedOwnershipError::Source {
                table: "world.asset_definition_direct_homes",
                ..
            })
        ));
    }
}
