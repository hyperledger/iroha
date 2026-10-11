//! Fixed native map roles and unpublished preparation drafts over the source archive.
//!
//! A draft can write redundant immutable objects, but never select a monetary head or
//! publish an archive manifest. Only its coordinator may retain/promote the descriptor.

use super::{map_tree::PersistentMapV1, *};

/// Protocol map selected by the native operation owner. Quota usage is a fixed array,
/// and issued Requests/held objects have separate custody indexes, never extra IMTs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreparationMapV1 {
    /// Permanent consumed-credit map of the selected core state.
    Consumed,
    /// Core or lineage-adjusted pending map selected by the coordinator.
    Pending,
    /// Shared ordinary Load/unload recovery map.
    Recovery,
    /// Fee-claim recovery map.
    Fee,
    /// Permanent Request-recorded blacklist-version history.
    BlacklistHistory,
}
impl PreparationMapV1 {
    const ALL: [Self; 5] = [
        Self::Consumed,
        Self::Pending,
        Self::Recovery,
        Self::Fee,
        Self::BlacklistHistory,
    ];
    const fn index(self) -> usize {
        match self {
            Self::Consumed => 0,
            Self::Pending => 1,
            Self::Recovery => 2,
            Self::Fee => 3,
            Self::BlacklistHistory => 4,
        }
    }
    fn state_root(self, state: &KagemushaWalletStateV1) -> [u8; 32] {
        match self {
            Self::Consumed => state.core.consumed_credit_root,
            Self::Pending => state.core.pending_outgoing_root,
            Self::Recovery => state.core.load_redeem_recovery_root,
            Self::Fee => state.core.fee_claim_root,
            Self::BlacklistHistory => state.rest.blacklist_history_root,
        }
    }
}

#[derive(Debug, Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::SourceMapsV1")]
pub(super) struct SourceMapsV1 {
    version: u16,
    maps: [PersistentMapV1; 5],
    quota_slots: [Option<KagemushaWalletQuotaUsageLeafV1>; 64],
}
impl Default for SourceMapsV1 {
    fn default() -> Self {
        Self {
            version: 1,
            maps: core::array::from_fn(|_| PersistentMapV1::default()),
            quota_slots: [None; 64],
        }
    }
}
impl SourceMapsV1 {
    pub(super) fn history(&self) -> &PersistentMapV1 {
        &self.maps[PreparationMapV1::BlacklistHistory.index()]
    }
    pub(super) fn pending(&self) -> &PersistentMapV1 {
        &self.maps[PreparationMapV1::Pending.index()]
    }
    pub(super) fn replace_pending(&mut self, pending: PersistentMapV1) {
        self.maps[PreparationMapV1::Pending.index()] = pending;
    }
    pub(super) fn require(&self, state: &KagemushaWalletStateV1) -> Result<(), Error> {
        state
            .validate()
            .map_err(|_| Error::WitnessLost("source map state"))?;
        if self.version != 1 {
            return Err(Error::WitnessLost("source map version"));
        }
        for role in PreparationMapV1::ALL {
            let map = &self.maps[role.index()];
            map.validate()?;
            if map.root() != role.state_root(state) {
                return Err(Error::WitnessLost("source map state root"));
            }
        }
        if self.quota_usage()?.root() != state.core.quota_usage_root {
            return Err(Error::WitnessLost("source quota array root"));
        }
        Ok(())
    }
    fn quota_usage(&self) -> Result<KagemushaWalletQuotaUsageArrayV1, Error> {
        KagemushaWalletQuotaUsageArrayV1::from_slots(self.quota_slots)
            .map_err(|_| Error::WitnessLost("source quota array layout"))
    }
}

// Keeps ObjectStore generic helpers monomorphized without exposing archive selection.
struct BorrowedStore<'a>(&'a mut dyn ObjectStore);
impl ObjectStore for BorrowedStore<'_> {
    fn read_object(&mut self, key: &[u8; 32], maximum: usize) -> Result<Vec<u8>, Error> {
        self.0.read_object(key, maximum)
    }
    fn write_object(&mut self, bytes: &[u8], maximum: usize) -> Result<[u8; 32], Error> {
        self.0.write_object(bytes, maximum)
    }
}

/// Unpublished map work under one coordinator-selected source and operation.
/// There is no public constructor, root setter, archive setter or descriptor importer.
/// Map updates return the actual G1 witnesses, including authenticated empty insertions
/// and relink/clear removals. Dropping this view discards all unpublished descriptors.
pub struct PreparationMapsV1<'a> {
    store: BorrowedStore<'a>,
    draft: SourceMapsV1,
    kind: KagemushaWalletOperationKindV1,
    refresh: Option<KagemushaWalletPolicyUpdateKindV1>,
}
impl<'a> PreparationMapsV1<'a> {
    pub(super) fn snapshot(&self) -> SourceMapsV1 {
        self.draft.clone()
    }
    pub(crate) fn store(&mut self) -> &mut dyn ObjectStore {
        self.store.0
    }
    pub(super) fn new(
        store: &'a mut dyn ObjectStore,
        selected: &SourceMapsV1,
        state: &KagemushaWalletStateV1,
        kind: KagemushaWalletOperationKindV1,
        refresh: Option<KagemushaWalletPolicyUpdateKindV1>,
    ) -> Result<Self, Error> {
        selected.require(state)?;
        if (kind == KagemushaWalletOperationKindV1::RefreshPolicy) != refresh.is_some() {
            return Err(Error::Invalid("preparation update selector"));
        }
        Ok(Self {
            store: BorrowedStore(store),
            draft: selected.clone(),
            kind,
            refresh,
        })
    }

    /// Authenticate one exact member of the selected/draft role.
    ///
    /// # Errors
    /// Missing/corrupt objects, invalid key, or absence of the requested member.
    pub fn membership(
        &mut self,
        role: PreparationMapV1,
        key: &[u8; 32],
    ) -> Result<
        (
            KagemushaWalletIndexedLeafV1,
            KagemushaWalletIndexedOpeningV1,
        ),
        Error,
    > {
        self.draft.maps[role.index()].membership(&mut self.store, key)
    }

    /// Authenticate absence through the actual low-leaf path, never a missing file.
    ///
    /// # Errors
    /// Missing/corrupt objects, invalid key or an existing member.
    pub fn non_membership(
        &mut self,
        role: PreparationMapV1,
        key: &[u8; 32],
    ) -> Result<
        (
            KagemushaWalletIndexedLeafV1,
            KagemushaWalletIndexedOpeningV1,
        ),
        Error,
    > {
        self.draft.maps[role.index()].non_membership(&mut self.store, key)
    }

    /// Derive a native insertion for a map owned by this operation.
    ///
    /// # Errors
    /// Wrong operation role, duplicate/invalid key/value, exhausted slots or storage failure.
    pub fn insert(
        &mut self,
        role: PreparationMapV1,
        key: [u8; 32],
        value: [u8; 32],
    ) -> Result<KagemushaWalletIndexedInsertV1, Error> {
        use KagemushaWalletOperationKindV1 as K;
        let allowed = match (self.kind, role) {
            (K::Receive, PreparationMapV1::Consumed)
            | (K::Send, PreparationMapV1::Pending | PreparationMapV1::Fee)
            | (K::Load | K::Unload, PreparationMapV1::Recovery) => true,
            (K::RefreshPolicy, PreparationMapV1::BlacklistHistory) => {
                self.refresh == Some(KagemushaWalletPolicyUpdateKindV1::Blacklist)
            }
            _ => false,
        };
        if !allowed {
            return Err(Error::Invalid("preparation insertion role"));
        }
        self.draft.maps[role.index()].insert(&mut self.store, key, value)
    }

    /// Derive Archive's actual pending-map removal, including physical-slot clearing.
    ///
    /// # Errors
    /// Another operation/role, missing member, invalid path or storage failure.
    pub fn remove(
        &mut self,
        role: PreparationMapV1,
        key: &[u8; 32],
    ) -> Result<KagemushaWalletIndexedRemoveV1, Error> {
        if self.kind != KagemushaWalletOperationKindV1::ArchiveSent
            || role != PreparationMapV1::Pending
        {
            return Err(Error::Invalid("preparation removal role"));
        }
        self.draft.maps[role.index()].remove(&mut self.store, key)
    }

    /// Read the exact aligned 64-slot quota array from this native draft.
    ///
    /// # Errors
    /// A stored slot layout is noncanonical or incomplete.
    pub fn quota_usage(&self) -> Result<KagemushaWalletQuotaUsageArrayV1, Error> {
        self.draft.quota_usage()
    }

    /// Retain the array produced by native Send charging or signed share rebuilding.
    /// Its root must also match the completely verified successor before publication.
    ///
    /// # Errors
    /// The selected operation does not own quota changes.
    pub fn set_quota_usage(
        &mut self,
        usage: &KagemushaWalletQuotaUsageArrayV1,
    ) -> Result<(), Error> {
        if self.kind != KagemushaWalletOperationKindV1::Send
            && !(self.kind == KagemushaWalletOperationKindV1::RefreshPolicy
                && self.refresh == Some(KagemushaWalletPolicyUpdateKindV1::QuotaShare))
        {
            return Err(Error::Invalid("preparation quota role"));
        }
        self.draft.quota_slots = *usage.slots();
        Ok(())
    }

    pub(super) fn finish(self, successor: &KagemushaWalletStateV1) -> Result<SourceMapsV1, Error> {
        self.draft.require(successor)?;
        Ok(self.draft)
    }
}

#[cfg(test)]
mod tests;
