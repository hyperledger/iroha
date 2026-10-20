//! Exact NFT and RWA grouping over both sealed original native images.
//! Local structural work grants no reference, economic, publication or finality authority.
use super::*;
use crate::state::authority_registry::{
    borrowed_controller_work::prepay_account_id, original_images::RawStorageImages,
};

/// Original canonical rows and every derived index retained through encoding.
pub(in super::super) struct CheckedNfts<'world> {
    world: &'world World,
    rows: CommittedStorageView<'world, NftId, NftValue>,
    owners: CommittedStorageView<'world, (AccountId, NftId), ()>,
    domains: CommittedStorageView<'world, (DomainId, NftId), ()>,
}
impl<'world> CheckedNfts<'world> {
    /// Check the sole both-image relation over these actual original readers.
    pub(in super::super) fn capture(
        world: &'world World,
        max_work: u64,
    ) -> Result<Self, GroupedOwnershipError> {
        let checked = Self {
            world,
            rows: world.nfts.try_committed_view_nonblocking()?,
            owners: world.nfts_by_owner.try_committed_view_nonblocking()?,
            domains: world.nfts_by_domain.try_committed_view_nonblocking()?,
        };
        let result =
            validate_original_nfts(&checked.rows, &checked.owners, &checked.domains, max_work);
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
    /// Borrow the same canonical rows whose exact indexes were checked.
    pub(in super::super) fn rows(&self) -> &CommittedStorageView<'world, NftId, NftValue> {
        &self.rows
    }
    /// Materialize every original native Result before first-refusal propagation.
    pub(in super::super) fn matches_current(&self) -> Result<bool, GroupedOwnershipError> {
        let rows = self.rows.try_matches_current(&self.world.nfts);
        let owners = self.owners.try_matches_current(&self.world.nfts_by_owner);
        let domains = self.domains.try_matches_current(&self.world.nfts_by_domain);
        let rows = rows?;
        let owners = owners?;
        let domains = domains?;
        Ok(rows && owners && domains)
    }
}
/// Original canonical rows and every derived index retained through encoding.
pub(in super::super) struct CheckedRwas<'world> {
    world: &'world World,
    rows: CommittedStorageView<'world, RwaId, RwaValue>,
    owners: CommittedStorageView<'world, (AccountId, RwaId), ()>,
    statuses: CommittedStorageView<'world, (Option<Name>, RwaId), ()>,
    frozen: CommittedStorageView<'world, (bool, RwaId), ()>,
}
impl<'world> CheckedRwas<'world> {
    /// Check the sole both-image relation over these actual original readers.
    pub(in super::super) fn capture(
        world: &'world World,
        max_work: u64,
    ) -> Result<Self, GroupedOwnershipError> {
        let checked = Self {
            world,
            rows: world.rwas.try_committed_view_nonblocking()?,
            owners: world.rwas_by_owner.try_committed_view_nonblocking()?,
            statuses: world.rwas_by_status.try_committed_view_nonblocking()?,
            frozen: world.rwas_by_frozen.try_committed_view_nonblocking()?,
        };
        let result = validate_original_rwas(
            &checked.rows,
            &checked.owners,
            &checked.statuses,
            &checked.frozen,
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
    /// Borrow the same canonical rows whose exact indexes were checked.
    pub(in super::super) fn rows(&self) -> &CommittedStorageView<'world, RwaId, RwaValue> {
        &self.rows
    }
    /// Materialize every original native Result before first-refusal propagation.
    pub(in super::super) fn matches_current(&self) -> Result<bool, GroupedOwnershipError> {
        let rows = self.rows.try_matches_current(&self.world.rwas);
        let owners = self.owners.try_matches_current(&self.world.rwas_by_owner);
        let statuses = self
            .statuses
            .try_matches_current(&self.world.rwas_by_status);
        let frozen = self.frozen.try_matches_current(&self.world.rwas_by_frozen);
        let rows = rows?;
        let owners = owners?;
        let statuses = statuses?;
        let frozen = frozen?;
        Ok(rows && owners && statuses && frozen)
    }
}
/// No-undo singleton NFT reference: domain63+63, Name63, Single Ed25519 owner.
/// This local schedule is not a worst-case bound, physical limit or validity rule.
pub(in crate::state) const NFT_WORK_PER_ROW: u64 = 4320;
/// No-undo singleton RWA reference: domain63+63, Some(Name63), Single Ed25519 owner.
/// Larger actual geometry may need more admitted local work without changing validity.
pub(in crate::state) const RWA_WORK_PER_ROW: u64 = 4608;
struct NftRwaWork(u64);
impl NftRwaWork {
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
trait BorrowedKey: mv::Key {
    fn prepay(&self, work: &mut NftRwaWork) -> Result<(), GroupedOwnershipError>;
}
impl<G: BorrowedKey, K: BorrowedKey> BorrowedKey for (G, K) {
    fn prepay(&self, work: &mut NftRwaWork) -> Result<(), GroupedOwnershipError> {
        self.0.prepay(work)?;
        self.1.prepay(work)
    }
}
impl BorrowedKey for DomainId {
    fn prepay(&self, work: &mut NftRwaWork) -> Result<(), GroupedOwnershipError> {
        work.prepay(self.name().as_ref().len())?;
        work.prepay(self.dataspace().as_ref().len())
    }
}
impl BorrowedKey for NftId {
    fn prepay(&self, work: &mut NftRwaWork) -> Result<(), GroupedOwnershipError> {
        self.domain().prepay(work)?;
        work.prepay(self.name().as_ref().len())
    }
}
impl BorrowedKey for RwaId {
    fn prepay(&self, work: &mut NftRwaWork) -> Result<(), GroupedOwnershipError> {
        self.domain().prepay(work)?;
        work.prepay(32)
    }
}
impl BorrowedKey for AccountId {
    fn prepay(&self, work: &mut NftRwaWork) -> Result<(), GroupedOwnershipError> {
        prepay_account_id(self, |amount| work.prepay(amount))
    }
}
impl BorrowedKey for Option<Name> {
    fn prepay(&self, work: &mut NftRwaWork) -> Result<(), GroupedOwnershipError> {
        work.prepay(1)?;
        if let Some(name) = self {
            work.prepay(name.as_ref().len())?;
        }
        Ok(())
    }
}
impl BorrowedKey for bool {
    fn prepay(&self, work: &mut NftRwaWork) -> Result<(), GroupedOwnershipError> {
        work.prepay(1)
    }
}
fn equal<K: BorrowedKey>(
    left: &K,
    right: &K,
    work: &mut NftRwaWork,
) -> Result<bool, GroupedOwnershipError> {
    left.prepay(work)?;
    right.prepay(work)?;
    Ok(left == right)
}
fn next_physical<I: ExactSizeIterator>(
    rows: &mut I,
    work: &mut NftRwaWork,
) -> Result<Option<I::Item>, GroupedOwnershipError> {
    if rows.len() == 0 {
        return Ok(None);
    }
    work.prepay(1)?;
    Ok(rows.next())
}
fn visit_original<'a, K: BorrowedKey, V: mv::Value>(
    rows: &'a impl RawStorageImages<K, V>,
    image: GroupImage,
    work: &mut NftRwaWork,
    mut inspect: impl FnMut(&'a K, &'a V, &mut NftRwaWork) -> Result<(), GroupedOwnershipError>,
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
fn lookup<'a, K: BorrowedKey, V: mv::Value>(
    rows: &'a impl RawStorageImages<K, V>,
    image: GroupImage,
    key: &K,
    work: &mut NftRwaWork,
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
fn contains<G: BorrowedKey, K: BorrowedKey>(
    groups: &impl RawStorageImages<(G, K), ()>,
    image: GroupImage,
    group: &G,
    member: &K,
    work: &mut NftRwaWork,
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

fn validate_id_group<K: BorrowedKey, V: mv::Value, G: BorrowedKey>(
    rows: &impl RawStorageImages<K, V>,
    groups: &impl RawStorageImages<(G, K), ()>,
    index: &'static str,
    project: impl for<'a> Fn(&'a K, &'a V) -> &'a G,
    work: &mut NftRwaWork,
) -> Result<(), GroupedOwnershipError> {
    for image in [GroupImage::Current, GroupImage::Predecessor] {
        let corrupt = |mismatch| GroupedOwnershipError::Corrupt {
            index,
            image,
            mismatch,
        };
        visit_original(rows, image, work, |id, value, work| {
            let found = contains(groups, image, project(id, value), id, work)?;
            if !found {
                return Err(corrupt(GroupMismatch::MissingMember));
            }
            Ok(())
        })?;
        visit_original(groups, image, work, |(group, id), (), work| {
            let Some(value) = lookup(rows, image, id, work)? else {
                return Err(corrupt(GroupMismatch::ForeignMember));
            };
            if !equal(project(id, value), group, work)? {
                return Err(corrupt(GroupMismatch::ForeignMember));
            }
            Ok(())
        })?;
    }
    Ok(())
}
/// Sole NFT owner then domain relation, each Current/Predecessor and source-before-inverse.
pub(in crate::state) fn validate_original_nfts(
    rows: &impl RawStorageImages<NftId, NftValue>,
    owners: &impl RawStorageImages<(AccountId, NftId), ()>,
    domains: &impl RawStorageImages<(DomainId, NftId), ()>,
    max_work: u64,
) -> Result<(), GroupedOwnershipError> {
    let mut work = NftRwaWork::bounded(max_work);
    validate_id_group(
        rows,
        owners,
        "world.nfts_by_owner",
        |_, value| &value.owned_by,
        &mut work,
    )?;
    validate_id_group(
        rows,
        domains,
        "world.nfts_by_domain",
        |id, _| id.domain(),
        &mut work,
    )
}
/// Sole RWA owner, status then frozen relation; None status remains a populated group key.
pub(in crate::state) fn validate_original_rwas(
    rows: &impl RawStorageImages<RwaId, RwaValue>,
    owners: &impl RawStorageImages<(AccountId, RwaId), ()>,
    statuses: &impl RawStorageImages<(Option<Name>, RwaId), ()>,
    frozen: &impl RawStorageImages<(bool, RwaId), ()>,
    max_work: u64,
) -> Result<(), GroupedOwnershipError> {
    let mut work = NftRwaWork::bounded(max_work);
    validate_id_group(
        rows,
        owners,
        "world.rwas_by_owner",
        |_, value| &value.owned_by,
        &mut work,
    )?;
    validate_id_group(
        rows,
        statuses,
        "world.rwas_by_status",
        |_, value| &value.status,
        &mut work,
    )?;
    validate_id_group(
        rows,
        frozen,
        "world.rwas_by_frozen",
        |_, value| &value.is_frozen,
        &mut work,
    )
}
#[cfg(test)]
#[path = "nfts_rwas/test_support.rs"]
pub(in crate::state) mod test_support;
#[cfg(test)]
#[path = "nfts_rwas/work_tests.rs"]
mod work_tests;
