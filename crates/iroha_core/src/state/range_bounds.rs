use core::ops::{Bound, RangeBounds};
use iroha_data_model::proof::ProofId;
use iroha_primitives::{cmpext::MinMaxExt, impl_as_dyn_key};
use super::*;
use crate::role::RoleIdWithOwner;
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
