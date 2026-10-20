use super::*;
use crate::role::RoleIdWithOwner;
use core::ops::{Bound, RangeBounds};
use iroha_data_model::proof::ProofId;
use iroha_primitives::{cmpext::MinMaxExt, impl_as_dyn_key};
/// Key for range queries over account for roles
#[derive(PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
pub struct RoleIdByAccount<'role> {
    account_id: &'role AccountId,
    role_id: MinMaxExt<&'role RoleId>,
}
/// Bounds for range quired over account for roles
pub struct RoleIdByAccountBounds<'role> {
    start: RoleIdByAccount<'role>,
    end: RoleIdByAccount<'role>,
}
impl<'role> RoleIdByAccountBounds<'role> {
    /// Create range bounds for range quires of roles over account
    pub fn new(account_id: &'role AccountId) -> Self {
        Self {
            start: RoleIdByAccount {
                account_id,
                role_id: MinMaxExt::Min,
            },
            end: RoleIdByAccount {
                account_id,
                role_id: MinMaxExt::Max,
            },
        }
    }
}
impl<'role> RangeBounds<dyn AsRoleIdByAccount + 'role> for RoleIdByAccountBounds<'role> {
    fn start_bound(&self) -> Bound<&(dyn AsRoleIdByAccount + 'role)> {
        Bound::Excluded(&self.start)
    }
    fn end_bound(&self) -> Bound<&(dyn AsRoleIdByAccount + 'role)> {
        Bound::Excluded(&self.end)
    }
}
impl AsRoleIdByAccount for RoleIdWithOwner {
    fn as_key(&self) -> RoleIdByAccount<'_> {
        RoleIdByAccount {
            account_id: &self.account,
            role_id: (&self.id).into(),
        }
    }
}
impl_as_dyn_key! {
    target: RoleIdWithOwner,
    key: RoleIdByAccount<'_>,
    trait: AsRoleIdByAccount
}
/// `DomainId` wrapper for fetching NFTs belonging to a domain from the global store
#[derive(PartialEq, Eq, Ord, PartialOrd, Copy, Clone)]
pub struct NftIdDomainCompare<'a> {
    domain_id: &'a DomainId,
    name: MinMaxExt<&'a Name>,
}
/// Bounds for range quired over NFTs by domain
pub struct NftByDomainBounds<'a> {
    start: NftIdDomainCompare<'a>,
    end: NftIdDomainCompare<'a>,
}
impl<'a> NftByDomainBounds<'a> {
    /// Create range bounds for range quires over NFTs by domain
    pub fn new(domain_id: &'a DomainId) -> Self {
        Self {
            start: NftIdDomainCompare {
                domain_id,
                name: MinMaxExt::Min,
            },
            end: NftIdDomainCompare {
                domain_id,
                name: MinMaxExt::Max,
            },
        }
    }
}
impl<'a> RangeBounds<dyn AsNftIdDomainCompare + 'a> for NftByDomainBounds<'a> {
    fn start_bound(&self) -> Bound<&(dyn AsNftIdDomainCompare + 'a)> {
        Bound::Excluded(&self.start)
    }
    fn end_bound(&self) -> Bound<&(dyn AsNftIdDomainCompare + 'a)> {
        Bound::Excluded(&self.end)
    }
}
impl AsNftIdDomainCompare for NftId {
    fn as_key(&self) -> NftIdDomainCompare<'_> {
        NftIdDomainCompare {
            domain_id: self.domain(),
            name: self.name().into(),
        }
    }
}
impl_as_dyn_key! {
    target: NftId,
    key: NftIdDomainCompare<'_>,
    trait: AsNftIdDomainCompare
}
/// `DomainId` wrapper for fetching RWAs belonging to a domain from the global store.
#[derive(PartialEq, Eq, Ord, PartialOrd, Copy, Clone)]
pub struct RwaIdDomainCompare<'a> {
    domain_id: &'a DomainId,
    hash: MinMaxExt<&'a Hash>,
}
/// Bounds for range queries over RWAs by domain.
pub struct RwaByDomainBounds<'a> {
    start: RwaIdDomainCompare<'a>,
    end: RwaIdDomainCompare<'a>,
}
impl<'a> RwaByDomainBounds<'a> {
    /// Create range bounds for range queries over RWAs by domain.
    pub fn new(domain_id: &'a DomainId) -> Self {
        Self {
            start: RwaIdDomainCompare {
                domain_id,
                hash: MinMaxExt::Min,
            },
            end: RwaIdDomainCompare {
                domain_id,
                hash: MinMaxExt::Max,
            },
        }
    }
}
impl<'a> RangeBounds<dyn AsRwaIdDomainCompare + 'a> for RwaByDomainBounds<'a> {
    fn start_bound(&self) -> Bound<&(dyn AsRwaIdDomainCompare + 'a)> {
        Bound::Excluded(&self.start)
    }
    fn end_bound(&self) -> Bound<&(dyn AsRwaIdDomainCompare + 'a)> {
        Bound::Excluded(&self.end)
    }
}
impl AsRwaIdDomainCompare for RwaId {
    fn as_key(&self) -> RwaIdDomainCompare<'_> {
        RwaIdDomainCompare {
            domain_id: self.domain(),
            hash: self.hash().into(),
        }
    }
}
impl_as_dyn_key! {
    target: RwaId,
    key: RwaIdDomainCompare<'_>,
    trait: AsRwaIdDomainCompare
}
/// `ProofId` wrapper for fetching proof records belonging to one backend.
#[derive(PartialEq, Eq, Ord, PartialOrd, Copy, Clone)]
pub struct ProofIdBackendCompare<'a> {
    backend: &'a str,
    proof_hash: MinMaxExt<&'a [u8; 32]>,
}
/// Bounds for range queries over proofs by backend.
pub struct ProofByBackendBounds<'a> {
    start: ProofIdBackendCompare<'a>,
    end: ProofIdBackendCompare<'a>,
}
impl<'a> ProofByBackendBounds<'a> {
    /// Create range bounds for proof queries by backend.
    pub fn new(backend: &'a str) -> Self {
        Self {
            start: ProofIdBackendCompare {
                backend,
                proof_hash: MinMaxExt::Min,
            },
            end: ProofIdBackendCompare {
                backend,
                proof_hash: MinMaxExt::Max,
            },
        }
    }
}
impl<'a> RangeBounds<dyn AsProofIdBackendCompare + 'a> for ProofByBackendBounds<'a> {
    fn start_bound(&self) -> Bound<&(dyn AsProofIdBackendCompare + 'a)> {
        Bound::Excluded(&self.start)
    }
    fn end_bound(&self) -> Bound<&(dyn AsProofIdBackendCompare + 'a)> {
        Bound::Excluded(&self.end)
    }
}
impl AsProofIdBackendCompare for ProofId {
    fn as_key(&self) -> ProofIdBackendCompare<'_> {
        ProofIdBackendCompare {
            backend: self.backend.as_str(),
            proof_hash: (&self.proof_hash).into(),
        }
    }
}
impl_as_dyn_key! {
    target: ProofId,
    key: ProofIdBackendCompare<'_>,
    trait: AsProofIdBackendCompare
}
/// `AccountId` wrapper for fetching assets beloning to an account from the global store
#[derive(PartialEq, Eq, Ord, PartialOrd, Copy, Clone)]
pub struct AssetIdAccountCompare<'a> {
    account_id: &'a AccountId,
    definition: MinMaxExt<&'a AssetDefinitionId>,
}
/// Bounds for range quired over assets by account
pub struct AssetByAccountBounds<'a> {
    start: AssetIdAccountCompare<'a>,
    end: AssetIdAccountCompare<'a>,
}
impl<'a> AssetByAccountBounds<'a> {
    /// Create range bounds for range quires over assets by account
    pub fn new(account_id: &'a AccountId) -> Self {
        Self {
            start: AssetIdAccountCompare {
                account_id,
                definition: MinMaxExt::Min,
            },
            end: AssetIdAccountCompare {
                account_id,
                definition: MinMaxExt::Max,
            },
        }
    }
}
impl<'a> RangeBounds<dyn AsAssetIdAccountCompare + 'a> for AssetByAccountBounds<'a> {
    fn start_bound(&self) -> Bound<&(dyn AsAssetIdAccountCompare + 'a)> {
        Bound::Excluded(&self.start)
    }
    fn end_bound(&self) -> Bound<&(dyn AsAssetIdAccountCompare + 'a)> {
        Bound::Excluded(&self.end)
    }
}
/// `AccountId + AssetDefinitionId` wrapper for fetching definition partitions in an account.
#[derive(PartialEq, Eq, Ord, PartialOrd, Copy, Clone)]
pub struct AssetIdAccountDefinitionCompare<'a> {
    account_id: &'a AccountId,
    definition: &'a AssetDefinitionId,
    scope: MinMaxExt<&'a AssetBalanceScope>,
}
/// Bounds for range queries over assets by account and definition.
pub struct AssetByAccountDefinitionBounds<'a> {
    start: AssetIdAccountDefinitionCompare<'a>,
    end: AssetIdAccountDefinitionCompare<'a>,
}
impl<'a> AssetByAccountDefinitionBounds<'a> {
    /// Create range bounds for range queries over assets by account and definition.
    pub fn new(account_id: &'a AccountId, definition: &'a AssetDefinitionId) -> Self {
        Self {
            start: AssetIdAccountDefinitionCompare {
                account_id,
                definition,
                scope: MinMaxExt::Min,
            },
            end: AssetIdAccountDefinitionCompare {
                account_id,
                definition,
                scope: MinMaxExt::Max,
            },
        }
    }
}
impl<'a> RangeBounds<dyn AsAssetIdAccountDefinitionCompare + 'a>
    for AssetByAccountDefinitionBounds<'a>
{
    fn start_bound(&self) -> Bound<&(dyn AsAssetIdAccountDefinitionCompare + 'a)> {
        Bound::Excluded(&self.start)
    }
    fn end_bound(&self) -> Bound<&(dyn AsAssetIdAccountDefinitionCompare + 'a)> {
        Bound::Excluded(&self.end)
    }
}
impl AsAssetIdAccountCompare for AssetId {
    fn as_key(&self) -> AssetIdAccountCompare<'_> {
        AssetIdAccountCompare {
            account_id: self.account(),
            definition: self.definition().into(),
        }
    }
}
impl AsAssetIdAccountDefinitionCompare for AssetId {
    fn as_key(&self) -> AssetIdAccountDefinitionCompare<'_> {
        AssetIdAccountDefinitionCompare {
            account_id: self.account(),
            definition: self.definition(),
            scope: self.scope().into(),
        }
    }
}
impl_as_dyn_key! {
    target: AssetId,
    key: AssetIdAccountCompare<'_>,
    trait: AsAssetIdAccountCompare
}
impl_as_dyn_key! {
    target: AssetId,
    key: AssetIdAccountDefinitionCompare<'_>,
    trait: AsAssetIdAccountDefinitionCompare
}
/// Bond-scoped projection of a bond entitlement key, for range queries over one bond.
#[derive(PartialEq, Eq, Ord, PartialOrd, Copy, Clone)]
pub struct BondEntitlementBondCompare<'a> {
    bond: &'a AssetDefinitionId,
    index: MinMaxExt<u16>,
    holder: MinMaxExt<&'a AccountId>,
}
/// Bounds for range queries over the entitlements of one bond, strictly after and before
/// optional entitlements of the same bond.
pub struct BondEntitlementsByBondBounds<'a> {
    start: BondEntitlementBondCompare<'a>,
    end: BondEntitlementBondCompare<'a>,
}
impl<'a> BondEntitlementsByBondBounds<'a> {
    /// Create range bounds over `bond`'s entitlements; `after` and `before` must belong to `bond`.
    pub fn new(
        bond: &'a AssetDefinitionId,
        after: Option<&'a iroha_data_model::bond::BondEntitlementId>,
        before: Option<&'a iroha_data_model::bond::BondEntitlementId>,
    ) -> Self {
        Self {
            start: after.map_or(
                BondEntitlementBondCompare {
                    bond,
                    index: MinMaxExt::Min,
                    holder: MinMaxExt::Min,
                },
                AsBondEntitlementBondCompare::as_key,
            ),
            end: before.map_or(
                BondEntitlementBondCompare {
                    bond,
                    index: MinMaxExt::Max,
                    holder: MinMaxExt::Max,
                },
                AsBondEntitlementBondCompare::as_key,
            ),
        }
    }
}
impl<'a> RangeBounds<dyn AsBondEntitlementBondCompare + 'a> for BondEntitlementsByBondBounds<'a> {
    fn start_bound(&self) -> Bound<&(dyn AsBondEntitlementBondCompare + 'a)> {
        Bound::Excluded(&self.start)
    }
    fn end_bound(&self) -> Bound<&(dyn AsBondEntitlementBondCompare + 'a)> {
        Bound::Excluded(&self.end)
    }
}
impl AsBondEntitlementBondCompare for iroha_data_model::bond::BondEntitlementId {
    fn as_key(&self) -> BondEntitlementBondCompare<'_> {
        BondEntitlementBondCompare {
            bond: &self.bond,
            index: self.index.into(),
            holder: (&self.holder).into(),
        }
    }
}
impl_as_dyn_key! {
    target: iroha_data_model::bond::BondEntitlementId,
    key: BondEntitlementBondCompare<'_>,
    trait: AsBondEntitlementBondCompare
}

/// Borrowed ordering key for an individual member in a derived pair index.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub struct PairIndexKey<'a, K, M> {
    key: &'a K,
    member: MinMaxExt<&'a M>,
}

/// Borrowed pair ordering used to seek directly to one index key's members.
///
/// This is the generic equivalent of the `impl_as_dyn_key!` adapters above.
pub trait AsPairIndex<K, M> {
    /// Return the pair's borrowed ordering key.
    fn as_pair_key(&self) -> PairIndexKey<'_, K, M>;
}

impl<K, M> AsPairIndex<K, M> for (K, M) {
    fn as_pair_key(&self) -> PairIndexKey<'_, K, M> {
        PairIndexKey {
            key: &self.0,
            member: MinMaxExt::Value(&self.1),
        }
    }
}
impl<K, M> AsPairIndex<K, M> for PairIndexKey<'_, K, M> {
    fn as_pair_key(&self) -> PairIndexKey<'_, K, M> {
        PairIndexKey {
            key: self.key,
            member: self.member,
        }
    }
}
impl<K: Ord, M: Ord> PartialEq for dyn AsPairIndex<K, M> + '_ {
    fn eq(&self, other: &Self) -> bool {
        self.as_pair_key() == other.as_pair_key()
    }
}
impl<K: Ord, M: Ord> Eq for dyn AsPairIndex<K, M> + '_ {}
impl<K: Ord, M: Ord> PartialOrd for dyn AsPairIndex<K, M> + '_ {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl<K: Ord, M: Ord> Ord for dyn AsPairIndex<K, M> + '_ {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.as_pair_key().cmp(&other.as_pair_key())
    }
}
impl<'a, K: 'a, M: 'a> core::borrow::Borrow<dyn AsPairIndex<K, M> + 'a> for (K, M) {
    fn borrow(&self) -> &(dyn AsPairIndex<K, M> + 'a) {
        self
    }
}

/// Prefix bounds over pair rows, with optional exclusive member cursors.
pub struct PairIndexBounds<'a, K, M> {
    start: PairIndexKey<'a, K, M>,
    end: PairIndexKey<'a, K, M>,
}
impl<'a, K, M> PairIndexBounds<'a, K, M> {
    /// Select all members of `key`.
    pub fn new(key: &'a K) -> Self {
        Self::between(key, None, None)
    }
    /// Select members strictly after an optional cursor.
    pub fn after(key: &'a K, after: Option<&'a M>) -> Self {
        Self::between(key, after, None)
    }
    /// Select members strictly before an optional cursor.
    pub fn before(key: &'a K, before: Option<&'a M>) -> Self {
        Self::between(key, None, before)
    }
    /// Select members strictly between the optional cursors.
    pub fn between(key: &'a K, after: Option<&'a M>, before: Option<&'a M>) -> Self {
        Self {
            start: PairIndexKey {
                key,
                member: after.map_or(MinMaxExt::Min, MinMaxExt::Value),
            },
            end: PairIndexKey {
                key,
                member: before.map_or(MinMaxExt::Max, MinMaxExt::Value),
            },
        }
    }
}
impl<'a, K, M> RangeBounds<dyn AsPairIndex<K, M> + 'a> for PairIndexBounds<'a, K, M> {
    fn start_bound(&self) -> Bound<&(dyn AsPairIndex<K, M> + 'a)> {
        Bound::Excluded(&self.start)
    }
    fn end_bound(&self) -> Bound<&(dyn AsPairIndex<K, M> + 'a)> {
        Bound::Excluded(&self.end)
    }
}

/// Test one membership with borrowed keys, without allocating or cloning either key.
pub fn index_contains<K: MvKey, M: MvKey>(
    index: &impl StorageReadOnly<(K, M), ()>,
    key: &K,
    member: &M,
) -> bool {
    index
        .get::<dyn AsPairIndex<K, M>>(&PairIndexKey {
            key,
            member: MinMaxExt::Value(member),
        })
        .is_some()
}

/// Return the stored member for an exact borrowed pair, without cloning either key.
pub fn index_get_member<'a, K: MvKey, M: MvKey>(
    index: &'a impl StorageReadOnly<(K, M), ()>,
    key: &K,
    member: &M,
) -> Option<&'a M> {
    let probe = PairIndexKey {
        key,
        member: MinMaxExt::Value(member),
    };
    let probe: &dyn AsPairIndex<K, M> = &probe;
    index
        .range::<dyn AsPairIndex<K, M>>((Bound::Included(probe), Bound::Included(probe)))
        .next()
        .map(|((_, member), ())| member)
}

/// Seek one key's members without scanning or copying adjacent index groups.
///
/// Bounds are consumed during the seek; yielded references borrow only `index`.
pub fn index_members<'a, K: MvKey, M: MvKey, S: StorageReadOnly<(K, M), ()>>(
    index: &'a S,
    key: &K,
) -> impl DoubleEndedIterator<Item = &'a M> + use<'a, K, M, S> {
    index
        .range::<dyn AsPairIndex<K, M>>(PairIndexBounds::new(key))
        .map(|((_, member), ())| member)
}
/// Seek members strictly after an optional cursor, borrowing only the index.
pub fn index_members_after<'a, K: MvKey, M: MvKey, S: StorageReadOnly<(K, M), ()>>(
    index: &'a S,
    key: &K,
    after: Option<&M>,
) -> impl DoubleEndedIterator<Item = &'a M> + use<'a, K, M, S> {
    index
        .range::<dyn AsPairIndex<K, M>>(PairIndexBounds::after(key, after))
        .map(|((_, member), ())| member)
}
/// Seek members strictly before an optional cursor, borrowing only the index.
pub fn index_members_before<'a, K: MvKey, M: MvKey, S: StorageReadOnly<(K, M), ()>>(
    index: &'a S,
    key: &K,
    before: Option<&M>,
) -> impl DoubleEndedIterator<Item = &'a M> + use<'a, K, M, S> {
    index
        .range::<dyn AsPairIndex<K, M>>(PairIndexBounds::before(key, before))
        .map(|((_, member), ())| member)
}

#[cfg(test)]
mod pair_index_tests {
    //! Prefix and cursor behavior for row-oriented derived indexes.
    use super::*;

    fn rows() -> Storage<(u64, u64), ()> {
        [(0, 99), (1, 10), (1, 20), (1, 30), (2, 0)]
            .into_iter()
            .map(|row| (row, ()))
            .collect()
    }

    #[test]
    fn pair_membership_uses_both_borrowed_components() {
        let rows = rows();
        let view = rows.view();
        assert!(index_contains(&view, &1, &20));
        assert!(!index_contains(&view, &1, &99));
        assert!(!index_contains(&view, &0, &20));
        assert!(!index_contains(&view, &3, &20));
        let found = {
            let key = 1;
            let member = 20;
            index_get_member(&view, &key, &member)
        };
        assert_eq!(found, Some(&20));
        assert!(index_get_member(&view, &1, &99).is_none());
    }

    #[test]
    fn pair_prefix_seeks_only_selected_members_in_both_directions() {
        let rows = rows();
        let view = rows.view();
        assert_eq!(
            index_members(&view, &1).copied().collect::<Vec<_>>(),
            [10, 20, 30]
        );
        assert_eq!(
            index_members(&view, &1).rev().copied().collect::<Vec<_>>(),
            [30, 20, 10]
        );
        assert!(index_members(&view, &3).next().is_none());
    }

    #[test]
    fn pair_cursors_are_exclusive_and_do_not_borrow_seek_inputs() {
        let rows = rows();
        let view = rows.view();
        let after = {
            let key = 1;
            let cursor = 20;
            index_members_after(&view, &key, Some(&cursor))
        };
        assert_eq!(after.copied().collect::<Vec<_>>(), [30]);
        assert_eq!(
            index_members_before(&view, &1, Some(&20))
                .copied()
                .collect::<Vec<_>>(),
            [10]
        );
        assert_eq!(
            index_members_after(&view, &1, Some(&15))
                .copied()
                .collect::<Vec<_>>(),
            [20, 30]
        );
        assert_eq!(index_members_before(&view, &1, None).count(), 3);
        assert_eq!(index_members_after(&view, &1, None).count(), 3);
    }

    #[test]
    fn pair_bounds_support_intersection_and_lexicographic_prefixes() {
        let rows = rows();
        let view = rows.view();
        let bounded = view.range::<dyn AsPairIndex<u64, u64>>(PairIndexBounds::between(
            &1,
            Some(&10),
            Some(&30),
        ));
        assert_eq!(
            bounded.map(|((_, member), ())| *member).collect::<Vec<_>>(),
            [20]
        );
        let rows: Storage<((u64, u64), u64), ()> =
            [(((0, 1), 99), ()), (((1, 0), 10), ()), (((1, 1), 20), ())]
                .into_iter()
                .collect();
        let view = rows.view();
        assert_eq!(
            index_members(&view, &(1, 0)).copied().collect::<Vec<_>>(),
            [10]
        );
    }
}
