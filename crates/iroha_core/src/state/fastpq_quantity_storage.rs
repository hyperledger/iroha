//! Transaction-local raw quantity write detection around the original MV journal.
//!
//! Read access preserves the original borrowed MV view. Every raw mutable lease,
//! insert and remove latches refusal independently of an enclosing callback.
//! Only the sibling quantity owner can use the separate typed write methods.
//! Dropping this owner drops the same MV checkpoint, so refusal rolls back with
//! the business transaction rather than leaking into the parent block.

use std::{borrow::Borrow, ops::RangeBounds};

use mv::{
    Key, Value,
    storage::{StorageReadOnly, Transaction},
};

use iroha_data_model::{
    account::AccountId,
    asset::{
        AssetDefinition, AssetDefinitionId, AssetId, AssetValue, Mintable,
        definition::AssetConfidentialPolicy,
    },
    isi::error::MintabilityError,
};
use iroha_model_base::metadata::Metadata;
use iroha_primitives::numeric::Quantity;

use super::fastpq_quantity_write_plan::{QuantityWriteKey, QuantityWritePlan};

/// A metadata and policy lease with no mutable quantity or identity projection.
///
/// The immutable definition remains inspectable. This type deliberately exposes
/// neither `DerefMut` nor a method returning the underlying mutable definition.
/// Only the original storage owner can construct the lease.
pub(crate) struct AssetDefinitionMetadataMut<'a> {
    definition: &'a mut AssetDefinition,
}

impl std::ops::Deref for AssetDefinitionMetadataMut<'_> {
    type Target = AssetDefinition;

    fn deref(&self) -> &Self::Target {
        self.definition
    }
}

impl AssetDefinitionMetadataMut<'_> {
    /// Edit application metadata without exposing quantity or balance-scope fields.
    pub(crate) fn metadata_mut(&mut self) -> &mut Metadata {
        self.definition.metadata_mut()
    }

    /// Consume the existing mintability authorization budget without changing supply.
    ///
    /// # Errors
    /// Refuses when the original definition no longer permits minting.
    pub(crate) fn consume_mintability(&mut self) -> Result<bool, MintabilityError> {
        self.definition.consume_mintability()
    }

    /// Set the already authorized mintability policy without granting a supply write.
    pub(crate) fn set_mintable(&mut self, mintable: Mintable) {
        self.definition.set_mintable(mintable);
    }

    /// Apply the already authorized owner change without changing any balance identity.
    pub(crate) fn set_owned_by(&mut self, owner: AccountId) {
        self.definition.set_owned_by(owner);
    }

    /// Apply an already validated confidential-policy transition without changing supply.
    pub(crate) fn set_confidential_policy(&mut self, policy: AssetConfidentialPolicy) {
        self.definition.set_confidential_policy(policy);
    }
}

impl QuantityStorageTransaction<'_, AssetDefinitionId, AssetDefinition> {
    /// Lease only mutation methods whose implementations cannot write total quantity.
    pub(super) fn metadata_mut(
        &mut self,
        key: &AssetDefinitionId,
    ) -> Option<AssetDefinitionMetadataMut<'_>> {
        self.inner
            .get_mut(key)
            .map(|definition| AssetDefinitionMetadataMut { definition })
    }

    /// Remove the actual definition under its one-shot lifecycle permit. A mismatched
    /// permit preserves business behavior while permanently refusing candidate capture.
    pub(super) fn retire_definition(
        &mut self,
        key: &AssetDefinitionId,
        incarnation: Option<iroha_data_model::nexus::AxtAssetIncarnationV1>,
        plan: &mut QuantityWritePlan<QuantityWriteKey, Quantity>,
    ) -> Option<AssetDefinition> {
        let permit = plan.consume_retirement(
            key,
            incarnation,
            self.inner.get(key).map(AssetDefinition::total_quantity),
        );
        if permit.is_err() {
            self.raw_write = true;
        }
        let previous = self.inner.remove(key.clone());
        if let Ok(permit) = permit {
            permit.applied();
        }
        previous
    }

    /// Perform one original supply write; failed capture cannot alter business state.
    /// A mismatch remains sticky in both the plan and the raw-write observation.
    pub(super) fn write_supply(
        &mut self,
        key: &AssetDefinitionId,
        after: Quantity,
        plan: &mut QuantityWritePlan<QuantityWriteKey, Quantity>,
    ) -> bool {
        let Some(before) = self
            .inner
            .get(key)
            .map(|definition| definition.total_quantity())
        else {
            return false;
        };
        let permit = plan.consume_supply(key, before, &after);
        if permit.is_err() {
            self.raw_write = true;
        }
        // No callback or externally supplied mutation lies between inspection and write.
        self.inner
            .get_mut(key)
            .expect("retained original definition")
            .total_quantity = after;
        if let Ok(permit) = permit {
            permit.applied();
        }
        true
    }
}

impl QuantityStorageTransaction<'_, AssetId, AssetValue> {
    /// Replace or remove one original balance under one exact ordered projection permit.
    /// A missing balance has quantity zero; physical absence remains owned by World.
    pub(super) fn write_balance(
        &mut self,
        key: AssetId,
        after: Option<AssetValue>,
        plan: &mut QuantityWritePlan<QuantityWriteKey, Quantity>,
    ) -> Option<AssetValue> {
        let zero = Quantity::zero();
        let before_quantity = self.inner.get(&key).map(AsRef::as_ref).unwrap_or(&zero);
        let after_quantity = after.as_ref().map(AsRef::as_ref).unwrap_or(&zero);
        let permit = plan.consume_balance(&key, before_quantity, after_quantity);
        if permit.is_err() {
            self.raw_write = true;
        }
        let previous = match after {
            Some(value) => self.inner.insert(key, value),
            None => self.inner.remove(key),
        };
        if let Ok(permit) = permit {
            permit.applied();
        }
        previous
    }
}

/// The original quantity storage transaction and a sticky raw-write observation.
pub(crate) struct QuantityStorageTransaction<'block, K: Key, V: Value> {
    inner: Transaction<'block, K, V>,
    raw_write: bool,
}

impl<'block, K: Key, V: Value> QuantityStorageTransaction<'block, K, V> {
    /// Retain the exact MV rollback owner without reconstructing its contents.
    pub(super) fn new(inner: Transaction<'block, K, V>) -> Self {
        Self {
            inner,
            raw_write: false,
        }
    }

    /// Whether any untyped mutation or mutable lease escaped the write ports.
    pub(super) const fn has_raw_write(&self) -> bool {
        self.raw_write
    }

    /// A raw mutable lease cannot inherit an enclosing quantity callback's authority.
    pub(crate) fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        if self.inner.get(key).is_some() {
            self.raw_write = true;
        }
        self.inner.get_mut(key)
    }

    /// Raw replacement remains valid business execution but refuses quantity export.
    pub(crate) fn insert(&mut self, key: K, value: V) -> Option<V> {
        self.raw_write = true;
        self.inner.insert(key, value)
    }

    /// Even an absent raw removal remains an explicit untyped write attempt.
    pub(crate) fn remove(&mut self, key: K) -> Option<V> {
        self.raw_write = true;
        self.inner.remove(key)
    }

    /// Apply exactly the original MV transaction after the outer owner observes refusal.
    pub(super) fn apply(self) {
        self.inner.apply();
    }

    // A callback flag, restored final balance or caller-supplied key must never
    // reset `raw_write` or turn an untyped lease into an owned mutation.
}

// Read-only dereferencing preserves original view/preimage/touched-key access.
// There is intentionally no DerefMut and no mutable-inner/into-inner accessor.
impl<'block, K: Key, V: Value> std::ops::Deref for QuantityStorageTransaction<'block, K, V> {
    type Target = Transaction<'block, K, V>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<K: Key, V: Value> StorageReadOnly<K, V> for QuantityStorageTransaction<'_, K, V> {
    type Iter<'a>
        = <Transaction<'a, K, V> as StorageReadOnly<K, V>>::Iter<'a>
    where
        Self: 'a;
    type RangeIter<'a>
        = <Transaction<'a, K, V> as StorageReadOnly<K, V>>::RangeIter<'a>
    where
        Self: 'a;

    fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.inner.get(key)
    }
    fn iter(&self) -> Self::Iter<'_> {
        self.inner.iter()
    }
    fn range<Q>(&self, bounds: impl RangeBounds<Q>) -> Self::RangeIter<'_>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.inner.range(bounds)
    }
    fn first_key_value(&self) -> Option<(&K, &V)> {
        self.inner.first_key_value()
    }
    fn last_key_value(&self) -> Option<(&K, &V)> {
        self.inner.last_key_value()
    }
    fn len(&self) -> usize {
        self.inner.len()
    }
}

#[cfg(test)]
mod tests {
    use super::super::fastpq_quantity_write_plan::{ExpectedQuantityWrite, QuantityWritePlanError};
    use super::*;
    use iroha_data_model::{Registrable, asset::AssetBalancePolicy};
    use iroha_model_base::domain::DomainId;
    use iroha_primitives::{json::Json, numeric::Quantity};
    use iroha_test_samples::{ALICE_ID, BOB_ID};
    use mv::storage::Storage;

    fn definition() -> (AssetDefinitionId, AssetDefinition) {
        let id = AssetDefinitionId::derive_from_components(
            DomainId::try_new("quantity-write-owner", "universal").unwrap(),
            "units".parse().unwrap(),
        );
        let mut definition =
            AssetDefinition::numeric(id.clone(), "Units", AssetBalancePolicy::Global, None)
                .build(&ALICE_ID);
        definition.total_quantity = Quantity::from(17_u32);
        (id, definition)
    }

    fn expected(
        key: QuantityWriteKey,
        before: u32,
        after: u32,
    ) -> ExpectedQuantityWrite<QuantityWriteKey, Quantity> {
        ExpectedQuantityWrite {
            key,
            before: Quantity::from(before),
            after: Quantity::from(after),
        }
    }

    #[test]
    fn original_balance_and_supply_stores_consume_one_ordered_repeated_key_plan() {
        let (id, definition) = definition();
        let alice = AssetId::of(id.clone(), ALICE_ID.clone());
        let bob = AssetId::of(id.clone(), BOB_ID.clone());
        let mut definitions = Storage::<AssetDefinitionId, AssetDefinition>::default();
        definitions.insert(id.clone(), definition);
        let mut balances = Storage::<AssetId, AssetValue>::default();
        balances.insert(alice.clone(), AssetValue::new(Quantity::from(10_u32)));
        let mut definition_block = definitions.block();
        let mut balance_block = balances.block();
        let mut definitions = QuantityStorageTransaction::new(definition_block.transaction());
        let mut balances = QuantityStorageTransaction::new(balance_block.transaction());
        let mut plan = QuantityWritePlan::new(
            vec![
                expected(QuantityWriteKey::Balance(alice.clone()), 10, 9),
                expected(QuantityWriteKey::Balance(bob.clone()), 0, 1),
                expected(QuantityWriteKey::Balance(alice.clone()), 9, 14),
                expected(QuantityWriteKey::Supply(id.clone()), 17, 22),
            ],
            4,
        )
        .unwrap();
        balances.write_balance(
            alice.clone(),
            Some(AssetValue::new(Quantity::from(9_u32))),
            &mut plan,
        );
        balances.write_balance(
            bob.clone(),
            Some(AssetValue::new(Quantity::from(1_u32))),
            &mut plan,
        );
        balances.write_balance(
            alice.clone(),
            Some(AssetValue::new(Quantity::from(14_u32))),
            &mut plan,
        );
        assert!(definitions.write_supply(&id, Quantity::from(22_u32), &mut plan));
        assert!(matches!(plan.finish(), Ok(())));
        assert!(!balances.has_raw_write());
        assert!(!definitions.has_raw_write());
        assert_eq!(
            balances.get(&alice).unwrap().as_ref(),
            &Quantity::from(14_u32)
        );
        assert_eq!(balances.get(&bob).unwrap().as_ref(), &Quantity::from(1_u32));
        assert_eq!(
            definitions.get(&id).unwrap().total_quantity(),
            &Quantity::from(22_u32)
        );
    }

    #[test]
    fn rejected_projection_preserves_business_write_and_latches_original_owner_failure() {
        let (id, definition) = definition();
        let alice = AssetId::of(id.clone(), ALICE_ID.clone());
        let mut balances = Storage::<AssetId, AssetValue>::default();
        balances.insert(alice.clone(), AssetValue::new(Quantity::from(10_u32)));
        let mut balance_block = balances.block();
        let mut balances = QuantityStorageTransaction::new(balance_block.transaction());
        let mut plan = QuantityWritePlan::new(
            vec![expected(QuantityWriteKey::Balance(alice.clone()), 10, 9)],
            1,
        )
        .unwrap();
        balances.write_balance(
            alice.clone(),
            Some(AssetValue::new(Quantity::from(8_u32))),
            &mut plan,
        );
        assert_eq!(
            balances.get(&alice).unwrap().as_ref(),
            &Quantity::from(8_u32)
        );
        assert!(balances.has_raw_write());
        assert!(matches!(
            plan.finish(),
            Err(QuantityWritePlanError::Mismatch)
        ));
        let mut definitions = Storage::<AssetDefinitionId, AssetDefinition>::default();
        definitions.insert(id.clone(), definition);
        let mut definition_block = definitions.block();
        let mut definitions = QuantityStorageTransaction::new(definition_block.transaction());
        let mut plan = QuantityWritePlan::new(
            vec![expected(QuantityWriteKey::Supply(id.clone()), 17, 22)],
            1,
        )
        .unwrap();
        assert!(definitions.write_supply(&id, Quantity::from(23_u32), &mut plan));
        assert_eq!(
            definitions.get(&id).unwrap().total_quantity(),
            &Quantity::from(23_u32)
        );
        assert!(definitions.has_raw_write());
        assert!(matches!(
            plan.finish(),
            Err(QuantityWritePlanError::Mismatch)
        ));
    }

    #[test]
    fn valid_callback_permits_cannot_clear_an_intervening_restored_raw_write() {
        let (id, _) = definition();
        let alice = AssetId::of(id, ALICE_ID.clone());
        let mut storage = Storage::<AssetId, AssetValue>::default();
        storage.insert(alice.clone(), AssetValue::new(Quantity::from(10_u32)));
        let mut block = storage.block();
        let mut transaction = QuantityStorageTransaction::new(block.transaction());
        let mut plan = QuantityWritePlan::new(
            vec![
                expected(QuantityWriteKey::Balance(alice.clone()), 10, 9),
                expected(QuantityWriteKey::Balance(alice.clone()), 9, 14),
            ],
            2,
        )
        .unwrap();
        let callback =
            |transaction: &mut QuantityStorageTransaction<'_, AssetId, AssetValue>,
             plan: &mut QuantityWritePlan<QuantityWriteKey, Quantity>| {
                transaction.write_balance(
                    alice.clone(),
                    Some(AssetValue::new(Quantity::from(9_u32))),
                    plan,
                );
                let raw = transaction.get_mut(&alice).unwrap();
                **raw = Quantity::from(99_u32);
                **raw = Quantity::from(9_u32);
                transaction.write_balance(
                    alice.clone(),
                    Some(AssetValue::new(Quantity::from(14_u32))),
                    plan,
                );
            };
        callback(&mut transaction, &mut plan);
        assert!(matches!(plan.finish(), Ok(())));
        assert!(
            transaction.has_raw_write(),
            "a completed port plan cannot clear the independent storage refusal"
        );
        drop(transaction);
        assert_eq!(block.get(&alice).unwrap().as_ref(), &Quantity::from(10_u32));
    }

    #[test]
    fn metadata_lease_preserves_quantity_and_exact_identity_through_every_allowed_method() {
        let (id, original) = definition();
        let spec = original.spec();
        let mut storage = Storage::<AssetDefinitionId, AssetDefinition>::default();
        storage.insert(id.clone(), original);
        let mut block = storage.block();
        let mut transaction = QuantityStorageTransaction::new(block.transaction());
        {
            let mut metadata = transaction.metadata_mut(&id).unwrap();
            metadata
                .metadata_mut()
                .insert("key".parse().unwrap(), Json::new("value"));
            metadata.set_mintable(Mintable::Once);
            assert!(metadata.consume_mintability().unwrap());
            assert!(metadata.consume_mintability().is_err());
            metadata.set_owned_by(BOB_ID.clone());
            metadata.set_confidential_policy(AssetConfidentialPolicy::convertible());
            assert_eq!(metadata.total_quantity(), &Quantity::from(17_u32));
            assert_eq!(metadata.spec(), spec);
            assert_eq!(metadata.id, id);
            assert_eq!(metadata.balance_scope_policy(), AssetBalancePolicy::Global);
            assert_eq!(metadata.owned_by(), &*BOB_ID);
            assert_eq!(metadata.mintable(), Mintable::Not);
        }
        assert!(!transaction.has_raw_write());
        transaction.apply();
        let applied = block.get(&id).unwrap();
        assert_eq!(applied.total_quantity(), &Quantity::from(17_u32));
        assert_eq!(applied.owned_by(), &*BOB_ID);
    }

    #[test]
    fn raw_supply_lease_stays_refused_after_restoration_and_metadata_access() {
        let (id, original) = definition();
        let mut storage = Storage::<AssetDefinitionId, AssetDefinition>::default();
        storage.insert(id.clone(), original);
        let mut block = storage.block();
        let mut transaction = QuantityStorageTransaction::new(block.transaction());
        {
            let definition = transaction.get_mut(&id).unwrap();
            definition.total_quantity = Quantity::from(99_u32);
            definition.total_quantity = Quantity::from(17_u32);
        }
        assert!(transaction.has_raw_write());
        transaction
            .metadata_mut(&id)
            .unwrap()
            .set_owned_by(BOB_ID.clone());
        assert!(transaction.has_raw_write());
        assert_eq!(
            transaction.get(&id).unwrap().total_quantity(),
            &Quantity::from(17_u32)
        );
        drop(transaction);
        assert_eq!(block.get(&id).unwrap().owned_by(), &*ALICE_ID);
        assert_eq!(
            block.get(&id).unwrap().total_quantity(),
            &Quantity::from(17_u32)
        );
    }

    #[test]
    fn reads_preserve_original_transaction_and_do_not_claim_mutation() {
        let mut storage = Storage::<u64, u64>::default();
        storage.insert(1, 10);
        let mut block = storage.block();
        let transaction = QuantityStorageTransaction::new(block.transaction());
        assert!(!transaction.has_raw_write());
        assert_eq!(transaction.get(&1), Some(&10));
        assert_eq!(transaction.get_before_transaction(&1), Some(&10));
        assert_eq!(transaction.iter().collect::<Vec<_>>(), vec![(&1, &10)]);
        assert_eq!(
            transaction.range(1..=1).collect::<Vec<_>>(),
            vec![(&1, &10)]
        );
        assert_eq!(transaction.first_key_value(), Some((&1, &10)));
        assert_eq!(transaction.last_key_value(), Some((&1, &10)));
        assert_eq!(transaction.len(), 1);
        assert!(!transaction.has_raw_write());
    }

    #[test]
    fn raw_lease_is_sticky_even_when_restored_before_return() {
        let mut storage = Storage::<u64, u64>::default();
        storage.insert(1, 10);
        let mut block = storage.block();
        let mut transaction = QuantityStorageTransaction::new(block.transaction());
        assert!(transaction.get_mut(&99).is_none());
        assert!(!transaction.has_raw_write());
        let value = transaction.get_mut(&1).unwrap();
        *value = 20;
        *value = 10;
        assert!(transaction.has_raw_write());
        assert_eq!(transaction.get(&1), Some(&10));
        assert_eq!(transaction.touched_entries().count(), 1);
    }

    #[test]
    fn insert_and_remove_cannot_launder_each_other_or_the_original_value() {
        let mut storage = Storage::<u64, u64>::default();
        storage.insert(1, 10);
        let mut block = storage.block();
        let mut transaction = QuantityStorageTransaction::new(block.transaction());
        assert_eq!(transaction.insert(1, 10), Some(10));
        assert!(transaction.has_raw_write());
        assert_eq!(transaction.insert(2, 20), None);
        assert_eq!(transaction.remove(2), Some(20));
        assert_eq!(transaction.remove(99), None);
        assert!(transaction.has_raw_write());
        assert_eq!(transaction.get(&1), Some(&10));
        assert_eq!(transaction.get(&2), None);
    }

    #[test]
    fn refusal_and_mutations_share_original_rollback_but_apply_preserves_business_state() {
        let mut storage = Storage::<u64, u64>::default();
        storage.insert(1, 10);
        let mut block = storage.block();
        {
            let mut transaction = QuantityStorageTransaction::new(block.transaction());
            transaction.insert(1, 20);
            assert!(transaction.has_raw_write());
        }
        assert_eq!(block.get(&1), Some(&10));
        let mut transaction = QuantityStorageTransaction::new(block.transaction());
        assert!(!transaction.has_raw_write());
        transaction.insert(1, 30);
        assert!(transaction.has_raw_write());
        transaction.apply();
        assert_eq!(block.get(&1), Some(&30));
    }
}
