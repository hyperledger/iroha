//! Exact definition/domain/group/policy relations with original direct-home authority.
//!
//! Both committed and frozen consumers share these sealed native-image checks.
//! Work is prepaid source inspection, not allocation or finalized authority.
//! TODO: join every original relation/cell/history to StatePublication and Kura.

use super::confidential_policies::{self, RetainedConfidentialPolicies};
use super::*;
use crate::state::authority_registry::{
    borrowed_controller_work::prepay_account_id, original_images::RawStorageImages,
};
use iroha_data_model::nexus::AxtAssetIncarnationV1;
use iroha_data_model::{
    asset::{AssetBalancePolicy, AssetDefinition, AssetDefinitionDirectHomeV1, AssetDefinitionId},
    domain::Domain,
};

/// Original canonical definitions checked against all definition lookup indexes.
pub(in super::super) struct CheckedAssetDefinitions<'world> {
    world: &'world World,
    homes: CommittedStorageView<'world, AssetDefinitionId, AssetDefinitionDirectHomeV1>,
    incarnations: CommittedStorageView<'world, AssetDefinitionId, AxtAssetIncarnationV1>,
    rows: CommittedStorageView<'world, AssetDefinitionId, AssetDefinition>,
    domains: CommittedStorageView<'world, DomainId, Domain>,
    contexts: CommittedStorageView<'world, AssetDefinitionId, DomainId>,
    by_domain: CommittedStorageView<'world, DomainId, BTreeSet<AssetDefinitionId>>,
    by_owner: CommittedStorageView<'world, AccountId, BTreeSet<AssetDefinitionId>>,
    confidential_policies: RetainedConfidentialPolicies<'world>,
}

impl<'world> CheckedAssetDefinitions<'world> {
    /// Check both retained images with bounded prepaid work and no live mutation.
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
            rows: world.asset_definitions.try_committed_view_nonblocking()?,
            domains: world.domains.try_committed_view_nonblocking()?,
            contexts: world
                .asset_definition_domains
                .try_committed_view_nonblocking()?,
            by_domain: world
                .domain_asset_definitions
                .try_committed_view_nonblocking()?,
            by_owner: world
                .asset_definitions_by_owner
                .try_committed_view_nonblocking()?,
            confidential_policies: RetainedConfidentialPolicies::retain(world)?,
        };
        let (transitions, counts) = checked.confidential_policies.originals();
        let result = validate_original_asset_definitions(
            &checked.rows,
            &checked.domains,
            &checked.contexts,
            &checked.by_domain,
            &checked.by_owner,
            transitions,
            counts,
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

    /// Borrow the exact canonical rows whose derived lookups were checked.
    pub(in super::super) fn rows(
        &self,
    ) -> &CommittedStorageView<'world, AssetDefinitionId, AssetDefinition> {
        &self.rows
    }

    /// Probe all original native owners before propagating any refusal.
    pub(in super::super) fn matches_current(&self) -> Result<bool, GroupedOwnershipError> {
        let rows = self.rows.try_matches_current(&self.world.asset_definitions);
        let domains = self.domains.try_matches_current(&self.world.domains);
        let contexts = self
            .contexts
            .try_matches_current(&self.world.asset_definition_domains);
        let by_domain = self
            .by_domain
            .try_matches_current(&self.world.domain_asset_definitions);
        let by_owner = self
            .by_owner
            .try_matches_current(&self.world.asset_definitions_by_owner);
        let [transitions, counts] = self.confidential_policies.current_results();
        let homes = self
            .homes
            .try_matches_current(&self.world.asset_definition_direct_homes);
        let incarnations = self
            .incarnations
            .try_matches_current(&self.world.axt_asset_incarnations);
        let homes = homes?;
        let incarnations = incarnations?;
        let rows = rows?;
        let domains = domains?;
        let contexts = contexts?;
        let by_domain = by_domain?;
        let by_owner = by_owner?;
        let transitions = transitions?;
        let counts = counts?;
        Ok(homes
            && incarnations
            && rows
            && domains
            && contexts
            && by_domain
            && by_owner
            && transitions
            && counts)
    }
}

/// One-row Single Ed25519/domain126/pending-window reference over both images.
/// Wider controllers and quadratic cuts may need more local admitted work; this
/// is not a row, policy, controller, gas, schema or ledger-validity maximum.
pub(in super::super) const ASSET_DEFINITION_WORK_PER_ROW: u64 = 3868;

/// Prepay the existing fixed sixteen UUID bytes before copying/comparing them.
/// The callback preserves the caller's exact local refusal and never reparses an id.
pub(super) fn prepay_asset_definition_id<E>(
    _: &AssetDefinitionId,
    mut prepay: impl FnMut(usize) -> Result<(), E>,
) -> Result<(), E> {
    prepay(16)
}

pub(super) struct AssetDefinitionWork(u64);
impl AssetDefinitionWork {
    pub(super) fn bounded(max_work: u64) -> Self {
        Self(max_work)
    }
    pub(super) fn prepay(&mut self, amount: usize) -> Result<(), GroupedOwnershipError> {
        let amount = u64::try_from(amount).map_err(|_| GroupedOwnershipError::WorkLimit)?;
        self.0 = self
            .0
            .checked_sub(amount)
            .ok_or(GroupedOwnershipError::WorkLimit)?;
        Ok(())
    }
    /// Work still prepaid for the caller after a shared relation consumed its share.
    pub(super) fn remaining(&self) -> u64 {
        self.0
    }
}

pub(super) trait AssetWorkKey: mv::Key {
    fn prepay(&self, work: &mut AssetDefinitionWork) -> Result<(), GroupedOwnershipError>;
}
impl AssetWorkKey for AssetDefinitionId {
    fn prepay(&self, work: &mut AssetDefinitionWork) -> Result<(), GroupedOwnershipError> {
        prepay_asset_definition_id(self, |amount| work.prepay(amount))
    }
}
impl AssetWorkKey for DomainId {
    fn prepay(&self, work: &mut AssetDefinitionWork) -> Result<(), GroupedOwnershipError> {
        work.prepay(self.name().as_ref().len())?;
        work.prepay(self.dataspace().as_ref().len())
    }
}
impl AssetWorkKey for AccountId {
    fn prepay(&self, work: &mut AssetDefinitionWork) -> Result<(), GroupedOwnershipError> {
        prepay_account_id(self, |amount| work.prepay(amount))
    }
}
impl AssetWorkKey for u64 {
    fn prepay(&self, work: &mut AssetDefinitionWork) -> Result<(), GroupedOwnershipError> {
        work.prepay(8)
    }
}
impl AssetWorkKey for (u64, AssetDefinitionId) {
    fn prepay(&self, work: &mut AssetDefinitionWork) -> Result<(), GroupedOwnershipError> {
        work.prepay(8)?;
        self.1.prepay(work)
    }
}

pub(super) fn equal<K: AssetWorkKey>(
    left: &K,
    right: &K,
    work: &mut AssetDefinitionWork,
) -> Result<bool, GroupedOwnershipError> {
    left.prepay(work)?;
    right.prepay(work)?;
    Ok(left == right)
}

pub(super) fn next_physical<I: ExactSizeIterator>(
    rows: &mut I,
    work: &mut AssetDefinitionWork,
) -> Result<Option<I::Item>, GroupedOwnershipError> {
    if rows.len() == 0 {
        return Ok(None);
    }
    work.prepay(1)?;
    Ok(rows.next())
}

pub(super) fn visit_original<'a, K: AssetWorkKey, V: mv::Value>(
    rows: &'a impl RawStorageImages<K, V>,
    image: GroupImage,
    work: &mut AssetDefinitionWork,
    mut inspect: impl FnMut(&'a K, &'a V, &mut AssetDefinitionWork) -> Result<(), GroupedOwnershipError>,
) -> Result<(), GroupedOwnershipError> {
    let mut current = rows.current_entries();
    while let Some((key, value)) = next_physical(&mut current, work)? {
        let mut masked = false;
        if image == GroupImage::Predecessor {
            let mut undo = rows.undo_entries();
            while let Some((prior_key, _)) = next_physical(&mut undo, work)? {
                masked |= equal(key, prior_key, work)?;
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

pub(super) fn lookup<'a, K: AssetWorkKey, V: mv::Value>(
    rows: &'a impl RawStorageImages<K, V>,
    image: GroupImage,
    key: &K,
    work: &mut AssetDefinitionWork,
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

fn contains(
    members: &BTreeSet<AssetDefinitionId>,
    key: &AssetDefinitionId,
    work: &mut AssetDefinitionWork,
) -> Result<bool, GroupedOwnershipError> {
    let mut members = members.iter();
    let mut found = false;
    while let Some(candidate) = next_physical(&mut members, work)? {
        found |= equal(key, candidate, work)?;
    }
    Ok(found)
}

fn optional_domain_equal(
    left: &Option<DomainId>,
    right: Option<&DomainId>,
    work: &mut AssetDefinitionWork,
) -> Result<bool, GroupedOwnershipError> {
    work.prepay(2)?;
    match (left.as_ref(), right) {
        (Some(left), Some(right)) => equal(left, right, work),
        (None, None) => Ok(true),
        _ => Ok(false),
    }
}

/// Check each changed direct-home key between the predecessor and current images.
/// A row is immutable for one incarnation and disappears only with that incarnation.
pub(super) fn validate_original_direct_home_transitions(
    homes: &impl RawStorageImages<AssetDefinitionId, AssetDefinitionDirectHomeV1>,
    incarnations: &impl RawStorageImages<AssetDefinitionId, AxtAssetIncarnationV1>,
    work: &mut AssetDefinitionWork,
) -> Result<(), GroupedOwnershipError> {
    let mut changed = homes.undo_entries();
    while let Some((id, _)) = next_physical(&mut changed, work)? {
        let before = lookup(homes, GroupImage::Predecessor, id, work)?;
        let after = lookup(homes, GroupImage::Current, id, work)?;
        let incarnation_before = lookup(incarnations, GroupImage::Predecessor, id, work)?;
        let incarnation_after = lookup(incarnations, GroupImage::Current, id, work)?;
        crate::state::validate_direct_home_transition(
            before,
            after,
            incarnation_before,
            incarnation_after,
        )
        .map_err(|_| GroupedOwnershipError::Source {
            table: "world.asset_definition_direct_homes",
            image: GroupImage::Current,
            reason: "direct home changed immutable predecessor authority",
        })?;
    }
    Ok(())
}

/// Check every direct-home row of one image against its exact definition incarnation.
pub(super) fn validate_original_direct_home_rows(
    homes: &impl RawStorageImages<AssetDefinitionId, AssetDefinitionDirectHomeV1>,
    definitions: &impl RawStorageImages<AssetDefinitionId, AssetDefinition>,
    incarnations: &impl RawStorageImages<AssetDefinitionId, AxtAssetIncarnationV1>,
    image: GroupImage,
    work: &mut AssetDefinitionWork,
) -> Result<(), GroupedOwnershipError> {
    visit_original(homes, image, work, |id, row, work| {
        let definition = lookup(definitions, image, id, work)?;
        let incarnation = lookup(incarnations, image, id, work)?;
        crate::state::direct_home_dataspace(Some(row), definition, incarnation).map_err(|_| {
            GroupedOwnershipError::Source {
                table: "world.asset_definition_direct_homes",
                image,
                reason: "direct home does not match its exact definition incarnation",
            }
        })?;
        Ok(())
    })
}

/// The sole complete definition/reference/group/policy relation over original images.
/// Phased Current/Predecessor order and all source/index predicates stay unchanged.
/// No accounts, embedded-id, alias, balance quantity or zk_assets rule is added.
pub(in crate::state) fn validate_original_asset_definitions(
    rows: &impl RawStorageImages<AssetDefinitionId, AssetDefinition>,
    domains: &impl RawStorageImages<DomainId, Domain>,
    contexts: &impl RawStorageImages<AssetDefinitionId, DomainId>,
    by_domain: &impl RawStorageImages<DomainId, BTreeSet<AssetDefinitionId>>,
    by_owner: &impl RawStorageImages<AccountId, BTreeSet<AssetDefinitionId>>,
    transitions: &impl RawStorageImages<(u64, AssetDefinitionId), ()>,
    counts: &impl RawStorageImages<u64, u32>,
    homes: &impl RawStorageImages<AssetDefinitionId, AssetDefinitionDirectHomeV1>,
    incarnations: &impl RawStorageImages<AssetDefinitionId, AxtAssetIncarnationV1>,
    max_work: u64,
) -> Result<(), GroupedOwnershipError> {
    let mut work = AssetDefinitionWork::bounded(max_work);
    validate_original_direct_home_transitions(homes, incarnations, &mut work)?;
    for image in [GroupImage::Current, GroupImage::Predecessor] {
        validate_original_direct_home_rows(homes, rows, incarnations, image, &mut work)?;
        let corrupt = |mismatch| GroupedOwnershipError::Corrupt {
            index: "world.asset_definition_domains",
            image,
            mismatch,
        };
        visit_original(rows, image, &mut work, |id, definition, work| {
            work.prepay(2)?; // balance policy and actual optional-domain tag
            let domain = definition.owning_domain().as_ref();
            let direct = lookup(homes, image, id, work)?.map(|row| row.dataspace_id);
            if definition.balance_scope_policy() == AssetBalancePolicy::DataspaceRestricted
                && domain.is_none()
                && direct.is_none()
            {
                return Err(GroupedOwnershipError::Source {
                    table: "world.asset_definitions",
                    image,
                    reason: "restricted definition has no owning domain",
                });
            }
            iroha_data_model::asset::AssetDefinitionHome::validate_definition(definition, direct)
                .map_err(|_| GroupedOwnershipError::Source {
                table: "world.asset_definitions",
                image,
                reason: "definition has no coherent authoritative home",
            })?;
            if let Some(domain) = domain {
                if lookup(domains, image, domain, work)?.is_none() {
                    return Err(GroupedOwnershipError::Source {
                        table: "world.asset_definitions",
                        image,
                        reason: "owning domain is absent",
                    });
                }
            }
            if !optional_domain_equal(
                definition.owning_domain(),
                lookup(contexts, image, id, work)?,
                work,
            )? {
                return Err(corrupt(if domain.is_some() {
                    GroupMismatch::MissingMember
                } else {
                    GroupMismatch::ForeignMember
                }));
            }
            Ok(())
        })?;
        visit_original(contexts, image, &mut work, |id, domain, work| {
            let Some(definition) = lookup(rows, image, id, work)? else {
                return Err(corrupt(GroupMismatch::ForeignMember));
            };
            if !optional_domain_equal(definition.owning_domain(), Some(domain), work)? {
                return Err(corrupt(GroupMismatch::ForeignMember));
            }
            Ok(())
        })?;
    }
    for image in [GroupImage::Current, GroupImage::Predecessor] {
        let corrupt = |mismatch| GroupedOwnershipError::Corrupt {
            index: "world.asset_definitions_by_owner",
            image,
            mismatch,
        };
        visit_original(rows, image, &mut work, |id, definition, work| {
            let Some(members) = lookup(by_owner, image, definition.owned_by(), work)? else {
                return Err(corrupt(GroupMismatch::MissingMember));
            };
            if !contains(members, id, work)? {
                return Err(corrupt(GroupMismatch::MissingMember));
            }
            Ok(())
        })?;
        visit_original(by_owner, image, &mut work, |owner, members, work| {
            work.prepay(1)?;
            if members.is_empty() {
                return Err(corrupt(GroupMismatch::EmptyGroup));
            }
            let mut members = members.iter();
            while let Some(id) = next_physical(&mut members, work)? {
                let Some(definition) = lookup(rows, image, id, work)? else {
                    return Err(corrupt(GroupMismatch::ForeignMember));
                };
                if !equal(definition.owned_by(), owner, work)? {
                    return Err(corrupt(GroupMismatch::ForeignMember));
                }
            }
            Ok(())
        })?;
    }
    for image in [GroupImage::Current, GroupImage::Predecessor] {
        let corrupt = |mismatch| GroupedOwnershipError::Corrupt {
            index: "world.domain_asset_definitions",
            image,
            mismatch,
        };
        visit_original(rows, image, &mut work, |id, definition, work| {
            work.prepay(1)?;
            if let Some(domain) = definition.owning_domain().as_ref() {
                let Some(members) = lookup(by_domain, image, domain, work)? else {
                    return Err(corrupt(GroupMismatch::MissingMember));
                };
                if !contains(members, id, work)? {
                    return Err(corrupt(GroupMismatch::MissingMember));
                }
            }
            Ok(())
        })?;
        visit_original(by_domain, image, &mut work, |domain, members, work| {
            work.prepay(1)?;
            if members.is_empty() {
                return Err(corrupt(GroupMismatch::EmptyGroup));
            }
            let mut members = members.iter();
            while let Some(id) = next_physical(&mut members, work)? {
                let Some(definition) = lookup(rows, image, id, work)? else {
                    return Err(corrupt(GroupMismatch::ForeignMember));
                };
                if !optional_domain_equal(definition.owning_domain(), Some(domain), work)? {
                    return Err(corrupt(GroupMismatch::ForeignMember));
                }
            }
            Ok(())
        })?;
    }
    confidential_policies::validate_original_confidential_policies(
        rows,
        transitions,
        counts,
        &mut work,
    )
}

#[cfg(test)]
pub(in crate::state) mod test_support;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod work_tests;

#[cfg(test)]
mod direct_home_original_tests {
    use super::*;
    use iroha_data_model::prelude::Registrable;
    use iroha_model_base::topology::DataSpaceId;
    use iroha_test_samples::ALICE_ID;

    #[test]
    fn direct_restricted_home_uses_exact_original_row_and_incarnation() {
        let mut world = test_support::world(false, None);
        let id = test_support::id(0);
        world
            .set_asset_definition_dataspace_for_testing(
                id.clone(),
                DataSpaceId::new((1_u64 << 53) + 7),
            )
            .unwrap();
        let mut definitions = world.asset_definitions.block();
        definitions.insert(
            id.clone(),
            AssetDefinition::numeric(
                id.clone(),
                "coin0",
                AssetBalancePolicy::DataspaceRestricted,
                None,
            )
            .build(&ALICE_ID),
        );
        definitions.commit();
        assert!(CheckedAssetDefinitions::capture(&world, 16_777_216).is_ok());
        assert!(matches!(
            CheckedAssetDefinitions::capture(&world, 0),
            Err(GroupedOwnershipError::WorkLimit)
        ));
        world.axt_asset_incarnations.insert(
            id,
            AxtAssetIncarnationV1::try_from_bytes(iroha_crypto::Hash::new([99]).into()).unwrap(),
        );
        assert!(matches!(
            CheckedAssetDefinitions::capture(&world, 16_777_216),
            Err(GroupedOwnershipError::Source {
                table: "world.asset_definition_direct_homes",
                ..
            })
        ));
    }

    #[test]
    fn direct_home_row_changed_in_place_is_refused_across_images() {
        let mut world = test_support::world(false, None);
        let id = test_support::id(0);
        world
            .set_asset_definition_dataspace_for_testing(id.clone(), DataSpaceId::new(7))
            .unwrap();
        assert!(CheckedAssetDefinitions::capture(&world, 16_777_216).is_ok());
        let mut homes = world.asset_definition_direct_homes.block();
        let mut moved = *homes.get(&id).unwrap();
        moved.dataspace_id = DataSpaceId::new(8);
        homes.insert(id, moved);
        homes.commit();
        assert!(matches!(
            CheckedAssetDefinitions::capture(&world, 16_777_216),
            Err(GroupedOwnershipError::Source {
                table: "world.asset_definition_direct_homes",
                image: GroupImage::Current,
                ..
            })
        ));
    }

    #[test]
    fn direct_home_capture_checks_both_images_without_allocating() {
        use crate::test_allocations::allocations_during;
        let mut world = test_support::world(false, None);
        world
            .set_asset_definition_dataspace_for_testing(test_support::id(0), DataSpaceId::new(7))
            .unwrap();
        let mut result = None;
        assert_eq!(
            allocations_during(|| {
                result = Some(CheckedAssetDefinitions::capture(&world, 16_777_216).map(|_| ()));
            }),
            0,
            "original direct-home inspection must retain its native rows without allocation"
        );
        assert_eq!(result.unwrap(), Ok(()));
    }

    #[test]
    fn retained_home_identity_changes_even_when_definition_rows_do_not() {
        let mut world = test_support::world(false, None);
        world
            .set_asset_definition_dataspace_for_testing(test_support::id(0), DataSpaceId::new(7))
            .unwrap();
        let checked = CheckedAssetDefinitions::capture(&world, 16_777_216).unwrap();
        let mut homes = world.asset_definition_direct_homes.block();
        homes.remove(test_support::id(0));
        homes.commit();
        assert!(!checked.matches_current().unwrap());
    }
}
