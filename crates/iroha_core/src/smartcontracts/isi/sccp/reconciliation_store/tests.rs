//! Reconciliation rows preserve original custody, rollback and ordered deadline work.

use super::*;
use crate::smartcontracts::isi::sccp::test_support::{blank_state, header};
use iroha_data_model::sccp::reconciliation::SccpReconciliationRatioV1;

fn open(closes_at_ms: u64) -> SccpReconciliationStateV1 {
    SccpReconciliationStateV1 {
        opened_at_ms: 0,
        closes_at_ms,
        forged_supply: 0,
        rho: None,
        settled_face: 0,
    }
}

#[test]
fn reconciliation_store_deduplicates_and_preserves_transaction_rollback() {
    let state = blank_state();
    let key = (SccpNetworkV1::EthereumMainnet, 1);
    let mut block = state.block(header(2));
    {
        let mut tx = block.transaction();
        put(&mut tx, key, open(50_000)).unwrap();
        prove(&mut tx, key, [1; 32], 7).unwrap();
        assert!(prove(&mut tx, key, [1; 32], 7).is_err());
        add_pending_refund(&mut tx, key, 9).unwrap();
        assert!(sub_pending_refund(&mut tx, key, 10).is_err());
        assert_eq!(pending_refunds(&*tx.world, &key), 9);
    }
    assert!(get(&block.world, &key).is_none());
    assert!(!proven(&block.world, key, &[1; 32]));
    assert_eq!(pending_refunds(&block.world, &key), 0);
    assert_eq!(earliest_due(&block.world, u64::MAX), None);
    {
        let mut tx = block.transaction();
        put(&mut tx, key, open(50_000)).unwrap();
        prove(&mut tx, key, [1; 32], 7).unwrap();
        add_pending_refund(&mut tx, key, 9).unwrap();
        sub_pending_refund(&mut tx, key, 9).unwrap();
        tx.apply();
    }
    assert!(proven(&block.world, key, &[1; 32]));
    assert_eq!(earliest_due(&block.world, 49_999), None);
    assert_eq!(
        earliest_due(&block.world, 50_000),
        Some((50_000, key.0, key.1))
    );
    let mut tx = block.transaction();
    let settled = SccpReconciliationStateV1 {
        rho: Some(SccpReconciliationRatioV1 {
            backing: 0,
            denominator: 1,
        }),
        ..open(50_000)
    };
    put(&mut tx, key, settled).unwrap();
    assert_eq!(earliest_due(&*tx.world, u64::MAX), None);
    assert_eq!(
        tx.world.sccp_reconciliation_due.iter_before_block().count(),
        0
    );
}

#[test]
fn reconciliation_record_invariants_reject_malformed_rates_and_keys() {
    let key = (SccpNetworkV1::TonMainnet, 1);
    assert!(!valid_record(&key, &open(0)));
    assert!(valid_record(&key, &open(1)));
    assert!(!valid_key(&(key.0, 0)));
    let mut record = open(1);
    record.settled_face = 1;
    assert!(!valid_record(&key, &record));
    record.settled_face = 0;
    record.rho = Some(SccpReconciliationRatioV1 {
        backing: 3,
        denominator: 2,
    });
    assert!(!valid_record(&key, &record));
    record.rho = Some(SccpReconciliationRatioV1 {
        backing: 0,
        denominator: 1,
    });
    assert!(valid_record(&key, &record));
}
