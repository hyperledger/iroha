//! Bounded, read-only access to immutable native settlement business receipts.

use super::*;
use iroha_data_model::{isi::SettlementReceipt, query::settlement::FindSettlementReceiptById};
use mv::storage::StorageReadOnly;

impl ValidSingularQuery for FindSettlementReceiptById {
    fn execute(&self, state: &impl StateReadOnly) -> Result<SettlementReceipt, Error> {
        let receipt = state
            .world()
            .settlement_receipts()
            .get(&self.id)
            .ok_or_else(|| Error::Find(FindError::SettlementReceipt(self.id.clone())))?;
        // Use the singular output owner so a 255-movement receipt or large
        // metadata cannot be cloned before its source/frame/allocation budget.
        own_singular_query_value(receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{kura::Kura, prelude::World, query::store::LiveQueryStore};
    use iroha_crypto::{Hash, HashOf};
    use iroha_data_model::{
        asset::{AssetBalanceScope, AssetId},
        block::BlockHeader,
        isi::{
            ResolvedSettlementMovement, ResolvedSettlementMovements, SettlementDetails,
            SettlementId,
        },
    };
    use iroha_model_base::{metadata::Metadata, topology::DataSpaceId};
    use iroha_primitives::numeric::Quantity;
    use iroha_test_samples::{ALICE_ID, BOB_ID};
    use nonzero_ext::nonzero;

    fn receipt(count: usize) -> SettlementReceipt {
        let definition = AssetDefinitionId::derive_from_components(
            DomainId::try_new("receipt", "universal").expect("domain"),
            "cash".parse().expect("name"),
        );
        let mut movements = (1..=count)
            .map(|index| {
                let scope = AssetBalanceScope::Dataspace(DataSpaceId::new(index as u64));
                ResolvedSettlementMovement {
                    source: AssetId::with_scope(definition.clone(), ALICE_ID.clone(), scope),
                    destination: AssetId::with_scope(definition.clone(), BOB_ID.clone(), scope),
                    quantity: Quantity::one(),
                    metadata: Metadata::default(),
                }
            })
            .collect::<Vec<_>>();
        movements.sort_by(|a, b| {
            (&a.source, a.destination.account()).cmp(&(&b.source, b.destination.account()))
        });
        SettlementReceipt {
            authority: ALICE_ID.clone(),
            metadata: Metadata::default(),
            block_height: 7,
            block_hash: HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
                b"settlement-query-block",
            )),
            executed_at_ms: 1234,
            details: SettlementDetails::Atomic(iroha_data_model::isi::AtomicSettlementDetails {
                movements: ResolvedSettlementMovements::try_from(movements)
                    .expect("canonical movements"),
                intent_hash: Hash::new(b"settlement-query-intent"),
                escrow_ids: Vec::new(),
            }),
        }
    }

    fn state() -> State {
        State::new(
            World::default(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        )
    }

    #[test]
    fn settlement_receipt_query_returns_every_exact_movement_without_mutating_history() {
        for count in [3, 255] {
            let state = state();
            let mut block = state.block(BlockHeader::new(nonzero!(8_u64), None, None, 1235, 0));
            let mut tx = block.transaction();
            let id = SettlementId::new(
                ALICE_ID.clone(),
                "query_business".parse().expect("reference"),
            );
            let expected = receipt(count);
            let before = norito::encode_canonical(&expected).expect("receipt frame");
            tx.world
                .settlement_receipts
                .insert(id.clone(), expected.clone());
            let query = FindSettlementReceiptById::new(id.clone());
            let result = ValidSingularQuery::execute(&query, &tx).expect("exact stored receipt");
            assert_eq!(result, expected);
            assert_eq!(result.details.movements().count(), count);
            let boxed = ExecuteSingularQuery::execute(SingularQueryBox::from(query), &tx)
                .expect("boxed query");
            assert_eq!(boxed, SingularQueryOutputBox::SettlementReceipt(expected));
            let mut detached = result;
            detached
                .metadata
                .insert("local".parse().expect("key"), Json::new("changed"));
            assert_ne!(
                norito::encode_canonical(&detached).expect("changed frame"),
                before
            );
            assert_eq!(
                norito::encode_canonical(
                    tx.world
                        .settlement_receipts
                        .get(&id)
                        .expect("retained receipt")
                )
                .expect("stored frame"),
                before
            );
            assert!(tx.world.internal_event_buf.is_empty());
            assert_eq!(tx.pending_transfer_transcript_count_for_testing(), 0);
        }
    }

    #[test]
    fn settlement_receipt_query_rejects_absence_without_creating_a_record() {
        let state = state();
        let mut block = state.block(BlockHeader::new(nonzero!(8_u64), None, None, 1235, 0));
        let tx = block.transaction();
        let id = SettlementId::new(
            ALICE_ID.clone(),
            "absent_business".parse().expect("reference"),
        );
        let query = FindSettlementReceiptById::new(id.clone());
        let error = ValidSingularQuery::execute(&query, &tx).expect_err("absent receipt");
        assert!(
            matches!(error, Error::Find(FindError::SettlementReceipt(missing)) if missing == id)
        );
        assert!(tx.world.settlement_receipts.get(&id).is_none());
        assert!(tx.world.internal_event_buf.is_empty());
        assert_eq!(tx.pending_transfer_transcript_count_for_testing(), 0);
    }

    #[test]
    fn settlement_receipt_query_enforces_the_actual_singular_output_frame_limit() {
        let state = state();
        let mut block = state.block(BlockHeader::new(nonzero!(8_u64), None, None, 1235, 0));
        let mut tx = block.transaction();
        let id = SettlementId::new(
            ALICE_ID.clone(),
            "bounded_business".parse().expect("reference"),
        );
        let expected = receipt(255);
        tx.world
            .settlement_receipts
            .insert(id.clone(), expected.clone());
        let query = FindSettlementReceiptById::new(id.clone());
        let large = Some(SingularQueryOutputLimits::new(
            1024 * 1024,
            16 * 1024 * 1024,
        ));
        let small = Some(SingularQueryOutputLimits::new(64, 16 * 1024 * 1024));
        assert!(
            super::super::singular_memory::execute_with_limits(small, || {
                ValidSingularQuery::execute(&query, &tx)
            })
            .is_err()
        );
        let result = super::super::singular_memory::execute_with_limits(large, || {
            ValidSingularQuery::execute(&query, &tx)
        })
        .expect("bounded complete receipt");
        assert_eq!(result, expected);
        assert_eq!(tx.world.settlement_receipts.get(&id), Some(&expected));
    }
}
