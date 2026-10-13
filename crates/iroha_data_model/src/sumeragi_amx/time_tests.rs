//! Signed AMX ledger-time bounds, deterministic due transitions and participant custody.

use super::*;

#[test]
fn sumeragi_amx_signed_expiry_is_mandatory_and_part_of_exact_intent() {
    let original = transaction(&[DS1, DS2], 20, 71);
    let mut changed = original.clone();
    changed.expires_at_ms += 1;
    assert_ne!(original.id().unwrap(), changed.id().unwrap());
    assert!(!original.begin().unwrap().matches(&changed));
    changed.expires_at_ms = 0;
    assert!(changed.validate().is_err());
    let json = norito::json::to_value(&original).unwrap();
    let mut fields = json.as_object().unwrap().clone();
    fields.remove("expires_at_ms");
    assert!(
        norito::json::from_value::<AmxTransactionV1>(norito::json::Value::Object(fields)).is_err()
    );
    let bytes = norito::encode_canonical(&original).unwrap();
    assert_eq!(
        norito::decode_canonical::<AmxTransactionV1>(&bytes).unwrap(),
        original
    );
}

#[test]
fn sumeragi_amx_begin_preserves_original_cadence_and_checked_time_window() {
    assert_eq!(amx_max_time_window_ms(1_000).unwrap(), 7_201_000);
    assert!(amx_max_time_window_ms(0).is_err());
    assert!(amx_max_time_window_ms(u64::MAX).is_err());
    let mut state = state_with(&[DS1, DS2]);
    let mut tx = transaction(&[DS1, DS2], 20, 72);
    for expiry in [0, 10_000, 7_211_001] {
        tx.expires_at_ms = expiry;
        assert!(state.begin(10, 10_000, 1_000, &tx).is_err());
        assert!(state.transactions.is_empty());
    }
    tx.expires_at_ms = 7_211_000;
    state.begin(10, 10_000, 1_000, &tx).unwrap();
    state.validate().unwrap();
    let bytes = norito::encode_canonical(&state).unwrap();
    let restored: SumeragiAmxState = norito::decode_canonical(&bytes).unwrap();
    assert_eq!(restored, state);
    assert_eq!(restored.transactions[0].original_cadence_ms, 1_000);
    let mut invalid = restored;
    invalid.transactions[0].original_cadence_ms = 999;
    assert!(
        invalid.validate().is_err(),
        "restored time window uses original admission cadence"
    );
}

#[test]
fn sumeragi_amx_time_boundary_is_exclusive_and_height_boundary_inclusive() {
    for (height, time_ms, commits) in [(20, 19_999, true), (20, 20_000, false), (21, 19_999, false)]
    {
        let mut state = state_with(&[DS1, DS2]);
        let mut tx = transaction(&[DS1, DS2], 20, 73);
        tx.expires_at_ms = 20_000;
        let id = tx.id().unwrap();
        state.begin(10, 10_000, 1_000, &tx).unwrap();
        let yes = |dataspace| {
            record_proof(
                instance(dataspace),
                &fixture(4),
                5,
                &prepared(id, dataspace, AmxVoteV1::Yes([7; 32])),
                &[],
            )
        };
        assert_eq!(
            state.relay_prepared(11, 11_000, &yes(DS1)).unwrap(),
            AmxRelayOutcome::Voted
        );
        let last = state.relay_prepared(height, time_ms, &yes(DS2)).unwrap();
        if commits {
            assert_eq!(
                last,
                AmxRelayOutcome::Decided(AmxDecisionV1 {
                    tx: id,
                    outcome: AmxOutcomeV1::Commit
                })
            );
            assert!(state.expire_one(height, time_ms, &id).is_err());
            state.validate().unwrap();
        } else {
            assert_eq!(
                last,
                AmxRelayOutcome::Voted,
                "late Yes must never decide Commit"
            );
            assert_eq!(
                state.expire_one(height, time_ms, &id).unwrap(),
                AmxDecisionV1 {
                    tx: id,
                    outcome: AmxOutcomeV1::Abort
                }
            );
            assert!(state.expire_one(height, time_ms, &id).is_err());
            assert_eq!(
                state.relay_prepared(height, time_ms, &yes(DS2)).unwrap(),
                AmxRelayOutcome::Ignored
            );
        }
    }
}

#[test]
fn sumeragi_amx_time_expiry_preserves_all_pending_rows_on_writer_refusal() {
    let mut state = state_with(&[DS1, DS2]);
    let mut transactions = Vec::new();
    for nonce in [74, 75] {
        let mut tx = transaction(&[DS1, DS2], 40, nonce);
        tx.expires_at_ms = 12_000;
        state.begin(10, 10_000, 1_000, &tx).unwrap();
        transactions.push(tx);
    }
    let original = state.clone();
    let id = state.transactions[0].begin.tx;
    assert!(state.expire_one(11, 11_999, &id).is_err());
    assert!(state.expire_one(11, 12_000, &[0; 32]).is_err());
    let mut calls = 0;
    assert_eq!(
        state.expire(11, 12_000, |_| {
            calls += 1;
            if calls == 2 {
                Err("original refusal")
            } else {
                Ok(())
            }
        }),
        Err("original refusal")
    );
    assert_eq!(
        state, original,
        "failed witness publication cannot prune time-expired obligations"
    );
    assert_eq!(state.expire(11, 12_000, |_| Ok::<_, ()>(())).unwrap(), 2);
    assert!(state.transactions.is_empty());
    for tx in transactions {
        assert!(
            state.begin(11, 12_000, 1_000, &tx).is_err(),
            "a pruned time-expired identity cannot Begin again"
        );
    }
}

#[test]
fn sumeragi_amx_participant_rejects_commit_at_signed_expiry_without_unlocking() {
    let mut tx = transfer(10, 76, [7, 8]);
    tx.expires_at_ms = 5_000;
    let begin = global_proof(2, &AmxRecordV1::Begin(tx.begin().unwrap()));
    let mut state = participant();
    let mut ledger = Ledger::with(&[(1, 20)]);
    state.prepare(&mut ledger, &tx, &begin).unwrap();
    let original_state = state.clone();
    let locked = ledger.clone();
    let late_commit = global_proof(5, &decision(&tx, AmxOutcomeV1::Commit));
    assert!(state.settle(&mut ledger, &late_commit).is_err());
    assert_eq!(state, original_state);
    assert_eq!(
        ledger, locked,
        "a rejected decision leaves the exact Yes escrow locked"
    );
    let abort = global_proof(5, &decision(&tx, AmxOutcomeV1::Abort));
    assert_eq!(
        state.settle(&mut ledger, &abort).unwrap(),
        AmxSettleOutcome::Released
    );
    assert_eq!(ledger.balances.get(&1), Some(&20));
    assert!(ledger.escrows.is_empty());
    assert_eq!(ledger.released, vec![tx.id().unwrap()]);
}

#[test]
fn sumeragi_amx_witness_classification_preserves_exact_schema_geometry() {
    assert_eq!(amx_record_witness_kind(&[]).unwrap(), None);
    assert_eq!(amx_record_witness_kind(&[0x00, 1]).unwrap(), None);
    for kind in [
        AmxRecordKind::Begin,
        AmxRecordKind::Prepared,
        AmxRecordKind::Decision,
    ] {
        let key = amx_record_witness_key(kind, [7; 32]);
        assert_eq!(amx_record_witness_kind(&key).unwrap(), Some(kind));
        assert!(amx_record_witness_kind(&key[..33]).is_err());
        let mut changed = key;
        changed[1] = 0;
        assert!(amx_record_witness_kind(&changed).is_err());
        let mut changed = key.to_vec();
        changed.push(0);
        assert!(amx_record_witness_kind(&changed).is_err());
    }
}
