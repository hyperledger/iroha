//! Physically admitted immutable complete tapes and allocation-free archive publication.
//!
//! The original execution pool funds exact canonical effect backing and nested
//! controller/quantity clones before any copy. Archive growth moves these owners;
//! it never clones payloads or allocates after the quantity callback returns.

use std::{alloc::Layout, ops::Deref};

use iroha_allocation::{
    AllocationBudget, AllocationCharge, AllocationReservation, ChargedBuffer, ChargedShared,
    ReservedChargedShared,
};
use iroha_crypto::Hash;
use iroha_data_model::fastpq::{
    FastpqExecutionAssetV1, FastpqExecutionBalanceV1, FastpqExecutionEffectContextV1,
    FastpqExecutionEffectKindV1, FastpqExecutionEffectV1, FastpqExecutionEffectsV1,
    FastpqExecutionSupplyChangeV1, FastpqExecutionTransferV1,
};
use iroha_data_model::{
    account::AccountId,
    asset::{AssetBalanceScope, AssetDefinitionId},
    nexus::AxtAssetIncarnationV1,
};
use iroha_primitives::numeric::Quantity;

use super::fastpq_quantity_capture::QuantityCaptureIssue;

/// Borrowed physical identity. This is not a wire type and never acquires a schema name.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct QuantityBalanceInput<'a> {
    pub(super) definition: &'a AssetDefinitionId,
    pub(super) incarnation: AxtAssetIncarnationV1,
    pub(super) account: &'a AccountId,
    pub(super) scope: AssetBalanceScope,
}

impl<'a> From<&'a FastpqExecutionBalanceV1> for QuantityBalanceInput<'a> {
    fn from(value: &'a FastpqExecutionBalanceV1) -> Self {
        Self {
            definition: &value.asset.definition,
            incarnation: value.asset.incarnation,
            account: &value.account,
            scope: value.scope,
        }
    }
}

/// Views of the values computed by the original transfer preparation.
#[derive(Clone, Copy)]
pub(super) struct QuantityTransferInput<'a> {
    pub(super) source: QuantityBalanceInput<'a>,
    pub(super) destination: QuantityBalanceInput<'a>,
    pub(super) amount: &'a Quantity,
    pub(super) source_before: &'a Quantity,
    pub(super) source_after: &'a Quantity,
    pub(super) destination_before: &'a Quantity,
    pub(super) destination_after: &'a Quantity,
}

/// Views of the values that the original supply preparation will actually apply.
#[derive(Clone, Copy)]
pub(super) struct QuantitySupplyInput<'a> {
    pub(super) balance: QuantityBalanceInput<'a>,
    pub(super) amount: &'a Quantity,
    pub(super) balance_before: &'a Quantity,
    pub(super) balance_after: &'a Quantity,
    pub(super) supply_before: &'a Quantity,
    pub(super) supply_after: &'a Quantity,
}

/// Allocation-free inputs; only the existing owned canonical DTO is serialized.
#[derive(Clone, Copy)]
pub(super) enum QuantityKindInput<'a> {
    Transfer(QuantityTransferInput<'a>),
    Mint(QuantitySupplyInput<'a>),
    Burn(QuantitySupplyInput<'a>),
    Retire(&'a AssetDefinitionId, AxtAssetIncarnationV1),
}

impl<'a> From<&'a FastpqExecutionEffectKindV1> for QuantityKindInput<'a> {
    fn from(kind: &'a FastpqExecutionEffectKindV1) -> Self {
        match kind {
            FastpqExecutionEffectKindV1::Retire(asset) => {
                Self::Retire(&asset.definition, asset.incarnation)
            }
            FastpqExecutionEffectKindV1::Transfer(value) => Self::Transfer(QuantityTransferInput {
                source: (&value.source).into(),
                destination: (&value.destination).into(),
                amount: &value.amount,
                source_before: &value.source_before,
                source_after: &value.source_after,
                destination_before: &value.destination_before,
                destination_after: &value.destination_after,
            }),
            FastpqExecutionEffectKindV1::Mint(value) | FastpqExecutionEffectKindV1::Burn(value) => {
                let input = QuantitySupplyInput {
                    balance: (&value.balance).into(),
                    amount: &value.amount,
                    balance_before: &value.balance_before,
                    balance_after: &value.balance_after,
                    supply_before: &value.supply_before,
                    supply_after: &value.supply_after,
                };
                if matches!(kind, FastpqExecutionEffectKindV1::Mint(_)) {
                    Self::Mint(input)
                } else {
                    Self::Burn(input)
                }
            }
        }
    }
}

impl<'a> QuantityKindInput<'a> {
    /// Borrow the exact original facts into the sole model commitment projection.
    pub(super) fn commitment_input(
        self,
    ) -> iroha_data_model::fastpq::FastpqExecutionEffectKindRefV1<'a> {
        use iroha_data_model::fastpq::{
            FastpqExecutionAssetRefV1 as Asset, FastpqExecutionBalanceRefV1 as Balance,
            FastpqExecutionEffectKindRefV1 as Kind, FastpqExecutionSupplyChangeRefV1 as Supply,
            FastpqExecutionTransferRefV1 as Transfer,
        };
        fn balance(value: QuantityBalanceInput<'_>) -> Balance<'_> {
            Balance {
                asset: Asset {
                    definition: value.definition,
                    incarnation: value.incarnation,
                },
                account: value.account,
                scope: value.scope,
            }
        }
        fn supply(value: QuantitySupplyInput<'_>) -> Supply<'_> {
            Supply {
                balance: balance(value.balance),
                amount: value.amount,
                balance_before: value.balance_before,
                balance_after: value.balance_after,
                supply_before: value.supply_before,
                supply_after: value.supply_after,
            }
        }
        match self {
            Self::Transfer(value) => Kind::Transfer(Transfer {
                source: balance(value.source),
                destination: balance(value.destination),
                amount: value.amount,
                source_before: value.source_before,
                source_after: value.source_after,
                destination_before: value.destination_before,
                destination_after: value.destination_after,
            }),
            Self::Mint(value) => Kind::Mint(supply(value)),
            Self::Burn(value) => Kind::Burn(supply(value)),
            Self::Retire(definition, incarnation) => Kind::Retire(Asset {
                definition,
                incarnation,
            }),
        }
    }
}

/// The concrete canonical Vec and every nested clone retain their original funding.
/// Only immutable access escapes; no safe operation can grow or extract the Vec.
pub(super) struct QuantityTape {
    wire: FastpqExecutionEffectsV1,
    // Physical payload above must drop before either backing or nested credits.
    _effects_charge: AllocationCharge,
    _nested_charges: ChargedBuffer<AllocationCharge>,
}

impl Deref for QuantityTape {
    type Target = FastpqExecutionEffectsV1;
    fn deref(&self) -> &Self::Target {
        &self.wire
    }
}
impl std::fmt::Debug for QuantityTape {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuantityTape")
            .field("effects", &self.wire.effects.len())
            .finish_non_exhaustive()
    }
}
impl QuantityTape {
    pub(super) fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self._effects_charge.belongs_to(budget)
            && self._nested_charges.belongs_to(budget)
            && self
                ._nested_charges
                .as_slice()
                .iter()
                .all(|charge| charge.belongs_to(budget))
    }
    pub(super) fn wire(&self) -> &FastpqExecutionEffectsV1 {
        &self.wire
    }

    /// Corrupt only the fixed entry identity for original-census adversarial controls.
    #[cfg(test)]
    pub(super) fn substitute_entry_hash_for_test(&mut self, entry_hash: Hash) {
        self.wire.context.entry.entry_hash = entry_hash;
    }

    #[cfg(test)]
    pub(super) fn prepare(
        context: FastpqExecutionEffectContextV1,
        prefix: &[FastpqExecutionEffectV1],
        added: &[FastpqExecutionEffectKindV1],
        authority_digest: Hash,
        authorization_context: Hash,
        max_effects: usize,
        budget: &AllocationBudget,
    ) -> Result<Self, QuantityCaptureIssue> {
        Self::prepare_inputs(
            context,
            prefix,
            added.iter().map(|kind| Ok(kind.into())),
            authority_digest,
            authorization_context,
            max_effects,
            budget,
        )
    }

    /// Retain one complete replacement before executing its new original effects.
    pub(super) fn prepare_inputs<'a, Inputs>(
        context: FastpqExecutionEffectContextV1,
        prefix: &[FastpqExecutionEffectV1],
        added: Inputs,
        authority_digest: Hash,
        authorization_context: Hash,
        max_effects: usize,
        budget: &AllocationBudget,
    ) -> Result<Self, QuantityCaptureIssue>
    where
        Inputs:
            Clone + ExactSizeIterator<Item = Result<QuantityKindInput<'a>, QuantityCaptureIssue>>,
    {
        let count = prefix
            .len()
            .checked_add(added.len())
            .ok_or(QuantityCaptureIssue::Capacity)?;
        if count > max_effects || u32::try_from(count).is_err() {
            return Err(QuantityCaptureIssue::Capacity);
        }
        if prefix
            .iter()
            .enumerate()
            .any(|(index, effect)| usize::try_from(effect.ordinal).ok() != Some(index))
        {
            return Err(QuantityCaptureIssue::InvalidFacts);
        }
        let mut nested_count = 0usize;
        let mut nested_bytes = 0usize;
        let mut add_layout = |layout: Layout| {
            nested_count = nested_count
                .checked_add(1)
                .ok_or(QuantityCaptureIssue::Capacity)?;
            nested_bytes = nested_bytes
                .checked_add(layout.size())
                .ok_or(QuantityCaptureIssue::Capacity)?;
            Ok(())
        };
        for effect in prefix {
            visit_layouts((&effect.kind).into(), &mut add_layout)?;
        }
        for kind in added.clone() {
            visit_layouts(kind?, &mut add_layout)?;
        }
        let backing = Layout::array::<FastpqExecutionEffectV1>(count)
            .map_err(|_| QuantityCaptureIssue::Capacity)?;
        let ledger = Layout::array::<AllocationCharge>(nested_count)
            .map_err(|_| QuantityCaptureIssue::Capacity)?;
        let bytes = nested_bytes
            .checked_add(backing.size())
            .and_then(|n| n.checked_add(ledger.size()))
            .ok_or(QuantityCaptureIssue::Capacity)?;
        let mut reservation = budget
            .try_reserve_bytes(bytes)
            .map_err(QuantityCaptureIssue::Admission)?;
        // Locals drop in reverse declaration order during a partial-clone refusal.
        let mut nested = ChargedBuffer::from_reservation(nested_count, &mut reservation)
            .map_err(QuantityCaptureIssue::from_prepaid)?;
        let mut effects = ChargedBuffer::from_reservation(count, &mut reservation)
            .map_err(QuantityCaptureIssue::from_prepaid)?;
        for original in prefix {
            let kind = clone_kind((&original.kind).into(), &mut reservation, &mut nested)?;
            effects.push_reserved(FastpqExecutionEffectV1 {
                ordinal: original.ordinal,
                authority_digest: original.authority_digest,
                authorization_context: original.authorization_context,
                kind,
            });
        }
        for (index, kind) in added.enumerate() {
            if effects.as_slice().len() == count {
                return Err(QuantityCaptureIssue::Capacity);
            }
            let kind = clone_kind(kind?, &mut reservation, &mut nested)?;
            effects.push_reserved(FastpqExecutionEffectV1 {
                ordinal: u32::try_from(prefix.len() + index)
                    .map_err(|_| QuantityCaptureIssue::Capacity)?,
                authority_digest,
                authorization_context,
                kind,
            });
        }
        if effects.as_slice().len() != count || reservation.remaining_bytes() != 0 {
            return Err(QuantityCaptureIssue::Capacity);
        }
        // SAFETY: the exact Vec/charge pair is immediately installed in this move-only
        // owner. Its only accessors are immutable. The wire payload is the first field,
        // so the Vec and all nested clones are destroyed before either set of credits.
        // No fallible operation runs between extraction and construction.
        #[allow(unsafe_code)]
        let (effects, charge) = unsafe { effects.into_allocation_parts() };
        Ok(Self {
            wire: FastpqExecutionEffectsV1 { context, effects },
            _effects_charge: charge,
            _nested_charges: nested,
        })
    }
}

fn visit_layouts(
    kind: QuantityKindInput<'_>,
    mut visit: impl FnMut(Layout) -> Result<(), QuantityCaptureIssue>,
) -> Result<(), QuantityCaptureIssue> {
    fn account(
        balance: QuantityBalanceInput<'_>,
        visit: &mut impl FnMut(Layout) -> Result<(), QuantityCaptureIssue>,
    ) -> Result<(), QuantityCaptureIssue> {
        let mut failure = None;
        balance
            .account
            .for_each_admission_clone_layout(|layout| {
                if failure.is_none() {
                    failure = visit(layout).err();
                }
            })
            .map_err(|_| QuantityCaptureIssue::Capacity)?;
        failure.map_or(Ok(()), Err)
    }
    let quantities = match kind {
        // Definition and incarnation are fixed-width values; retirement retains no
        // controller, quantity, or output-sized temporary allocation.
        QuantityKindInput::Retire(_, _) => return Ok(()),
        QuantityKindInput::Transfer(value) => {
            account(value.source, &mut visit)?;
            account(value.destination, &mut visit)?;
            [
                value.amount,
                value.source_before,
                value.source_after,
                value.destination_before,
                value.destination_after,
            ]
        }
        QuantityKindInput::Mint(value) | QuantityKindInput::Burn(value) => {
            account(value.balance, &mut visit)?;
            [
                value.amount,
                value.balance_before,
                value.balance_after,
                value.supply_before,
                value.supply_after,
            ]
        }
    };
    for quantity in quantities {
        visit(
            quantity
                .admission_clone_layout()
                .map_err(|_| QuantityCaptureIssue::Capacity)?,
        )?;
    }
    Ok(())
}
fn retain(
    layout: Layout,
    reservation: &mut AllocationReservation,
    ledger: &mut ChargedBuffer<AllocationCharge>,
) -> Result<(), QuantityCaptureIssue> {
    let charge = reservation
        .try_split(layout)
        .map_err(|_| QuantityCaptureIssue::Capacity)?;
    ledger.try_push(charge).map_err(|charge| {
        drop(charge);
        QuantityCaptureIssue::Capacity
    })
}
fn clone_balance(
    value: QuantityBalanceInput<'_>,
    reservation: &mut AllocationReservation,
    ledger: &mut ChargedBuffer<AllocationCharge>,
) -> Result<FastpqExecutionBalanceV1, QuantityCaptureIssue> {
    let mut failure = None;
    value
        .account
        .for_each_admission_clone_layout(|layout| {
            if failure.is_none() {
                failure = retain(layout, reservation, ledger).err();
            }
        })
        .map_err(|_| QuantityCaptureIssue::Capacity)?;
    if let Some(error) = failure {
        return Err(error);
    }
    Ok(FastpqExecutionBalanceV1 {
        asset: FastpqExecutionAssetV1 {
            definition: value.definition.clone(), // fixed identity, no nested allocation
            incarnation: value.incarnation,
        },
        account: value
            .account
            .try_clone_for_admission()
            .map_err(|_| QuantityCaptureIssue::Capacity)?,
        scope: value.scope,
    })
}
fn clone_quantity(
    value: &Quantity,
    reservation: &mut AllocationReservation,
    ledger: &mut ChargedBuffer<AllocationCharge>,
) -> Result<Quantity, QuantityCaptureIssue> {
    retain(
        value
            .admission_clone_layout()
            .map_err(|_| QuantityCaptureIssue::Capacity)?,
        reservation,
        ledger,
    )?;
    value
        .try_clone_for_admission()
        .map_err(|_| QuantityCaptureIssue::Capacity)
}
fn clone_kind(
    kind: QuantityKindInput<'_>,
    reservation: &mut AllocationReservation,
    ledger: &mut ChargedBuffer<AllocationCharge>,
) -> Result<FastpqExecutionEffectKindV1, QuantityCaptureIssue> {
    Ok(match kind {
        QuantityKindInput::Retire(definition, incarnation) => {
            FastpqExecutionEffectKindV1::Retire(FastpqExecutionAssetV1 {
                definition: definition.clone(),
                incarnation,
            })
        }
        QuantityKindInput::Transfer(value) => {
            FastpqExecutionEffectKindV1::Transfer(FastpqExecutionTransferV1 {
                source: clone_balance(value.source, reservation, ledger)?,
                destination: clone_balance(value.destination, reservation, ledger)?,
                amount: clone_quantity(value.amount, reservation, ledger)?,
                source_before: clone_quantity(value.source_before, reservation, ledger)?,
                source_after: clone_quantity(value.source_after, reservation, ledger)?,
                destination_before: clone_quantity(value.destination_before, reservation, ledger)?,
                destination_after: clone_quantity(value.destination_after, reservation, ledger)?,
            })
        }
        QuantityKindInput::Mint(value) | QuantityKindInput::Burn(value) => {
            let cloned = FastpqExecutionSupplyChangeV1 {
                balance: clone_balance(value.balance, reservation, ledger)?,
                amount: clone_quantity(value.amount, reservation, ledger)?,
                balance_before: clone_quantity(value.balance_before, reservation, ledger)?,
                balance_after: clone_quantity(value.balance_after, reservation, ledger)?,
                supply_before: clone_quantity(value.supply_before, reservation, ledger)?,
                supply_after: clone_quantity(value.supply_after, reservation, ledger)?,
            };
            if matches!(kind, QuantityKindInput::Mint(_)) {
                FastpqExecutionEffectKindV1::Mint(cloned)
            } else {
                FastpqExecutionEffectKindV1::Burn(cloned)
            }
        }
    })
}

/// Small sorted archive with exact admitted backing; absent maps allocate nothing.
pub(super) struct QuantityArchiveMap<V> {
    rows: Option<ChargedBuffer<(Hash, V)>>,
    frozen: Option<ChargedShared<FrozenQuantityArchive<V>>>,
}

/// The same original immutable map backing after its completed source finalizer.
/// No Clone/extraction/mutation API exists for the payload. Shared handles retain
/// the original control allocation, original map and every nested tape charge.
pub(super) struct FrozenQuantityArchive<V> {
    rows: Option<ChargedBuffer<(Hash, V)>>,
}

impl<V> FrozenQuantityArchive<V> {
    pub(super) fn rows(&self) -> &[(Hash, V)] {
        self.rows.as_ref().map_or(&[][..], ChargedBuffer::as_slice)
    }
}

impl<V> std::fmt::Debug for FrozenQuantityArchive<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FrozenQuantityArchive")
            .field("entries", &self.rows().len())
            .finish()
    }
}
impl<V> Default for QuantityArchiveMap<V> {
    fn default() -> Self {
        Self {
            rows: None,
            frozen: None,
        }
    }
}
impl<V> std::fmt::Debug for QuantityArchiveMap<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuantityArchiveMap")
            .field("entries", &self.len())
            .finish()
    }
}
impl<V> QuantityArchiveMap<V> {
    pub(super) fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        match &self.frozen {
            Some(frozen) => {
                frozen.belongs_to(budget)
                    && frozen
                        .rows
                        .as_ref()
                        .is_none_or(|rows| rows.belongs_to(budget))
            }
            None => self
                .rows
                .as_ref()
                .is_none_or(|rows| rows.belongs_to(budget)),
        }
    }
    fn rows(&self) -> &[(Hash, V)] {
        self.frozen.as_ref().map_or_else(
            || self.rows.as_ref().map_or(&[][..], ChargedBuffer::as_slice),
            |frozen| frozen.rows(),
        )
    }
    pub(super) fn is_frozen(&self) -> bool {
        self.frozen.is_some()
    }
    pub(super) fn retains_frozen(
        &self,
        original: &ChargedShared<FrozenQuantityArchive<V>>,
    ) -> bool {
        self.frozen
            .as_ref()
            .is_some_and(|current| ChargedShared::ptr_eq(current, original))
    }
    /// Move only original backing into a previously admitted shell. Finalization
    /// is one-shot and grants no finality or proof capability.
    pub(super) fn freeze(
        &mut self,
        shell: ReservedChargedShared<FrozenQuantityArchive<V>>,
    ) -> Result<ChargedShared<FrozenQuantityArchive<V>>, QuantityCaptureIssue> {
        if self.is_frozen() {
            return Err(QuantityCaptureIssue::InvalidFacts);
        }
        let original = shell.initialize(FrozenQuantityArchive {
            rows: self.rows.take(),
        });
        self.frozen = Some(original.clone());
        Ok(original)
    }
    pub(super) fn len(&self) -> usize {
        self.rows().len()
    }
    pub(super) fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub(super) fn get(&self, hash: &Hash) -> Option<&V> {
        self.rows()
            .binary_search_by_key(hash, |(key, _)| *key)
            .ok()
            .map(|index| &self.rows()[index].1)
    }
    pub(super) fn iter(&self) -> impl ExactSizeIterator<Item = (&Hash, &V)> {
        self.rows().iter().map(|(key, value)| (key, value))
    }
    pub(super) fn reserve(
        capacity: usize,
        budget: &AllocationBudget,
    ) -> Result<ChargedBuffer<(Hash, V)>, QuantityCaptureIssue> {
        ChargedBuffer::new(capacity, budget).map_err(QuantityCaptureIssue::from_buffer)
    }
    pub(super) fn for_each_mut(&mut self, mut visit: impl FnMut(&mut V)) {
        assert!(
            !self.is_frozen(),
            "completed quantity source has immutable backing"
        );
        if let Some(rows) = &mut self.rows {
            for (_, value) in rows.as_mut_slice() {
                visit(value);
            }
        }
    }
    /// Install pre-admitted successor backing without cloning any retained payload.
    pub(super) fn grow(&mut self, mut successor: ChargedBuffer<(Hash, V)>) {
        assert!(!self.is_frozen(), "completed quantity source cannot grow");
        assert!(successor.as_slice().is_empty() && successor.capacity() >= self.len());
        if let Some(previous) = &mut self.rows {
            for row in previous.drain_all() {
                successor.push_reserved(row);
            }
        }
        self.rows = Some(successor);
    }
    /// Replace/insert inside the capacity already reserved before callback execution.
    pub(super) fn insert_reserved(&mut self, hash: Hash, value: V) {
        assert!(
            !self.is_frozen(),
            "completed quantity source cannot replace a tape"
        );
        let rows = self
            .rows
            .as_mut()
            .expect("original reserved archive backing");
        match rows.as_slice().binary_search_by_key(&hash, |(key, _)| *key) {
            Ok(index) => {
                rows.as_mut_slice()[index].1 = value;
            }
            Err(_) => {
                rows.push_reserved((hash, value));
                rows.as_mut_slice().sort_unstable_by_key(|(key, _)| *key);
            }
        }
    }
    /// Transfer complete pending replacements after World application with no allocation.
    pub(super) fn apply_pending(
        &mut self,
        mut pending: Self,
        mut successor: ChargedBuffer<(Hash, V)>,
    ) {
        assert!(
            !self.is_frozen() && !pending.is_frozen(),
            "completed quantity source cannot apply another child"
        );
        assert!(
            successor.as_slice().is_empty() && successor.capacity() >= self.len() + pending.len()
        );
        if let Some(previous) = &mut self.rows {
            for (hash, value) in previous.drain_all() {
                if pending.get(&hash).is_none() {
                    successor.push_reserved((hash, value));
                }
            }
        }
        if let Some(rows) = &mut pending.rows {
            for row in rows.drain_all() {
                successor.push_reserved(row);
            }
        }
        successor
            .as_mut_slice()
            .sort_unstable_by_key(|(key, _)| *key);
        self.rows = Some(successor);
    }
}
impl<V> std::ops::Index<&Hash> for QuantityArchiveMap<V> {
    type Output = V;
    fn index(&self, hash: &Hash) -> &V {
        self.get(hash).expect("retained quantity entry")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completed_map_moves_original_backing_into_exact_prepaid_shared_shell() {
        let map_bytes = Layout::array::<(Hash, u64)>(1).unwrap().size();
        let shell_layout = ChargedShared::<FrozenQuantityArchive<u64>>::allocation_layout();
        let budget = AllocationBudget::new(map_bytes + shell_layout.size());
        let foreign = AllocationBudget::new(map_bytes + shell_layout.size());
        let key = Hash::new(b"original completed entry");
        let mut map = QuantityArchiveMap::default();
        map.grow(QuantityArchiveMap::reserve(1, &budget).unwrap());
        map.insert_reserved(key, 7_u64);
        let original = map.rows().as_ptr();
        let mut reservation = budget.try_reserve(shell_layout).unwrap();
        let shell = ChargedShared::reserve_from(&mut reservation).unwrap();
        let owner = map.freeze(shell).unwrap();
        assert_eq!(owner.rows().as_ptr(), original);
        assert_eq!(map.rows().as_ptr(), original);
        assert!(map.retains_frozen(&owner));
        assert!(map.belongs_to(&budget));
        assert!(!map.belongs_to(&foreign));
        assert!(owner.belongs_to(&budget));
        assert!(!owner.belongs_to(&foreign));
        assert_eq!(budget.reserved_bytes(), map_bytes + shell_layout.size());
        drop(map);
        assert_eq!(owner.rows(), &[(key, 7)]);
        assert_eq!(budget.reserved_bytes(), map_bytes + shell_layout.size());
        let final_owner = owner.clone();
        assert!(ChargedShared::ptr_eq(&owner, &final_owner));
        drop(owner);
        assert_eq!(budget.reserved_bytes(), map_bytes + shell_layout.size());
        drop(final_owner);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn completed_map_refuses_second_freeze_and_returns_only_unused_shell_credit() {
        let shell_layout = ChargedShared::<FrozenQuantityArchive<u64>>::allocation_layout();
        let budget = AllocationBudget::new(shell_layout.size() * 2);
        let mut map = QuantityArchiveMap::<u64>::default();
        let mut first = budget.try_reserve(shell_layout).unwrap();
        let owner = map
            .freeze(ChargedShared::reserve_from(&mut first).unwrap())
            .unwrap();
        let mut second = budget.try_reserve(shell_layout).unwrap();
        assert!(matches!(
            map.freeze(ChargedShared::reserve_from(&mut second).unwrap()),
            Err(QuantityCaptureIssue::InvalidFacts)
        ));
        assert!(map.retains_frozen(&owner));
        assert_eq!(budget.reserved_bytes(), shell_layout.size());
        drop(map);
        drop(owner);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn sorted_archive_growth_and_complete_replacement_only_move_original_payloads() {
        let budget = AllocationBudget::new(8192);
        let first = Hash::new(b"first");
        let second = Hash::new(b"second");
        let mut parent = QuantityArchiveMap::default();
        parent.grow(QuantityArchiveMap::reserve(2, &budget).unwrap());
        parent.insert_reserved(second, 20_u64);
        parent.insert_reserved(first, 10_u64);
        let mut pending = QuantityArchiveMap::default();
        pending.grow(QuantityArchiveMap::reserve(1, &budget).unwrap());
        pending.insert_reserved(first, 11_u64);
        let successor = QuantityArchiveMap::reserve(3, &budget).unwrap();
        let peak_before_apply = budget.peak_reserved_bytes();
        parent.apply_pending(pending, successor);
        assert_eq!(parent.len(), 2);
        assert_eq!(parent.get(&first), Some(&11));
        assert_eq!(parent.get(&second), Some(&20));
        assert_eq!(
            budget.peak_reserved_bytes(),
            peak_before_apply,
            "publication never reacquires credits"
        );
        assert_eq!(
            budget.reserved_bytes(),
            Layout::array::<(Hash, u64)>(3).unwrap().size()
        );
        let keys = parent.iter().map(|(key, _)| *key).collect::<Vec<_>>();
        assert!(keys.windows(2).all(|pair| pair[0] < pair[1]));
        drop(parent);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn rejected_archive_growth_preserves_old_storage_and_original_charges() {
        let bytes = Layout::array::<(Hash, u64)>(1).unwrap().size();
        let budget = AllocationBudget::new(bytes);
        let key = Hash::new(b"retained");
        let mut map: QuantityArchiveMap<u64> = QuantityArchiveMap::default();
        map.grow(QuantityArchiveMap::reserve(1, &budget).unwrap());
        map.insert_reserved(key, 9);
        assert!(QuantityArchiveMap::<u64>::reserve(2, &budget).is_err());
        assert_eq!(budget.reserved_bytes(), bytes);
        assert_eq!(map.get(&key), Some(&9));
        drop(map);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}
