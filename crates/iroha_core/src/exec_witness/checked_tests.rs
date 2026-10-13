//! Checked ordinary witness drain preserves raw content and rejects unfinished overlays.

use super::*;
use iroha_data_model::fastpq::{TransferDeltaTranscript, TransferSmtWitness};
use iroha_test_samples::{ALICE_ID, BOB_ID};
use std::sync::TryLockError;

fn transcript(hash: Hash, seed: u8) -> TransferTranscript {
    let delta = TransferDeltaTranscript {
        from_account: (*ALICE_ID).clone(),
        to_account: (*BOB_ID).clone(),
        asset_definition: AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            format!("rose_{seed}").parse().unwrap(),
        ),
        amount: Quantity::from(1_u32),
        from_balance_before: Quantity::from(10_u32),
        from_balance_after: Quantity::from(9_u32),
        to_balance_before: Quantity::zero(),
        to_balance_after: Quantity::from(1_u32),
        from_smt_witness: TransferSmtWitness::new(
            [seed; 32],
            [seed.wrapping_add(1); 32],
            vec![seed],
            vec![[seed; 32]],
        ),
        to_smt_witness: TransferSmtWitness::default(),
    };
    let digest = crate::fastpq::poseidon_preimage_digest(&delta, &hash);
    TransferTranscript {
        batch_hash: hash,
        deltas: vec![delta],
        authority_digest: crate::fastpq::authority_digest(&ALICE_ID),
        poseidon_preimage_digest: Some(digest),
    }
}

fn record_marker() {
    with_active_slot(|witness| {
        witness.reads.insert(vec![2], vec![20]);
        witness.reads.insert(vec![1], vec![10]);
        witness.writes.insert(vec![4], Vec::new());
        witness.writes.insert(vec![3], vec![30]);
    });
}

fn assert_inactive_empty() {
    let g = lock_slot();
    assert!(!g.active);
    assert!(g.reads.is_empty());
    assert!(g.writes.is_empty());
    assert!(g.fastpq_transcripts.is_empty());
}

#[test]
fn checked_drain_validates_raw_map_under_lock_before_returning_exact_content() {
    let _guard = exec_witness_guard();
    start_block();
    let first = Hash::prehashed([0x81; Hash::LENGTH]);
    let second = Hash::prehashed([0x82; Hash::LENGTH]);
    let expected = BTreeMap::from([
        (second, vec![transcript(second, 3)]),
        (first, vec![transcript(first, 1), transcript(first, 2)]),
    ]);
    synchronize_fastpq_transcripts(&expected);
    record_marker();
    let map_address: *const BTreeMap<Hash, Vec<TransferTranscript>> = {
        let g = lock_slot();
        &raw const g.fastpq_transcripts
    };
    let mut calls = 0;
    let witness = drain_exec_witness_checked(|raw| {
        calls += 1;
        assert!(matches!(slot().try_lock(), Err(TryLockError::WouldBlock)));
        assert!(std::ptr::eq(raw, map_address));
        assert_eq!(raw, &expected);
        Ok(())
    })
    .unwrap();
    assert_eq!(calls, 1);
    assert_eq!(witness.fastpq_transcripts, map_to_bundles(expected));
    assert_eq!(
        witness.reads,
        vec![
            ExecKv {
                key: vec![1],
                value: vec![10]
            },
            ExecKv {
                key: vec![2],
                value: vec![20]
            },
        ]
    );
    assert_eq!(
        witness.writes,
        vec![
            ExecKv {
                key: vec![3],
                value: vec![30]
            },
            ExecKv {
                key: vec![4],
                value: Vec::new()
            },
        ]
    );
    assert!(witness.fastpq_batches.is_empty());
    assert_inactive_empty();
}

#[test]
fn checked_drain_does_not_repair_missing_digest_even_when_validator_accepts_it() {
    let _guard = exec_witness_guard();
    start_block();
    let hash = Hash::new(b"checked drain retains exact optional digest");
    let mut raw = transcript(hash, 4);
    raw.poseidon_preimage_digest = None;
    record_fastpq_transcript(&raw);
    let witness = drain_exec_witness_checked(|map| {
        assert_eq!(map[&hash][0].poseidon_preimage_digest, None);
        Ok(())
    })
    .unwrap();
    assert_eq!(witness.fastpq_transcripts[0].transcripts, vec![raw]);
    assert_inactive_empty();
}

#[test]
fn rejected_missing_finalized_digest_is_observed_raw_and_discards_every_record() {
    let _guard = exec_witness_guard();
    start_block();
    let hash = Hash::new(b"removed finalized digest must not be repaired");
    let expected = transcript(hash, 5);
    let mut altered = expected.clone();
    altered.poseidon_preimage_digest = None;
    record_fastpq_transcript(&altered);
    record_marker();
    let error = drain_exec_witness_checked(|raw| {
        assert_eq!(raw[&hash], vec![altered]);
        assert_ne!(raw[&hash], vec![expected]);
        Err("sealed optional digest differs".to_owned())
    })
    .unwrap_err();
    assert_eq!(error, "sealed optional digest differs");
    assert_inactive_empty();
    record_marker();
    synchronize_fastpq_transcripts(&BTreeMap::from([(hash, vec![transcript(hash, 6)])]));
    assert_inactive_empty();
    let rejected = drain_exec_witness();
    assert!(rejected.reads.is_empty());
    assert!(rejected.writes.is_empty());
    assert!(rejected.fastpq_transcripts.is_empty());
}

#[test]
fn checked_drain_rejects_empty_and_populated_nested_overlays_before_validation() {
    let _guard = exec_witness_guard();
    for populated in [false, true] {
        for commit in [false, true] {
            start_block();
            record_marker();
            let hash = Hash::new(b"overlay final capture is incomplete");
            record_fastpq_transcript(&transcript(hash, 7));
            let outer = begin_exec_witness_overlay();
            let inner = begin_exec_witness_overlay();
            if populated {
                record_marker();
                synchronize_fastpq_transcripts(&BTreeMap::from([(
                    hash,
                    vec![transcript(hash, 8)],
                )]));
            }
            let error = drain_exec_witness_checked(|_| {
                panic!("a pending overlay must reject before inspecting partial global state")
            })
            .unwrap_err();
            assert!(error.contains("pending current-thread overlay"));
            assert_inactive_empty();
            if commit {
                inner.commit();
                outer.commit();
            } else {
                drop(inner);
                drop(outer);
            }
            EXEC_WITNESS_OVERLAYS.with(|overlays| assert!(overlays.borrow().is_empty()));
            assert_inactive_empty();
            start_block();
            record_marker();
            let fresh = drain_exec_witness_checked(|raw| {
                assert!(raw.is_empty());
                Ok(())
            })
            .unwrap();
            assert_eq!(fresh.reads.len(), 2);
            assert_eq!(fresh.writes.len(), 2);
        }
    }
}

#[test]
fn checked_drain_uses_only_committed_overlay_replacements() {
    let _guard = exec_witness_guard();
    for commit in [false, true] {
        start_block();
        let original_hash = Hash::new(b"original exact source");
        let replacement_hash = Hash::new(b"replacement exact source");
        let original = BTreeMap::from([(original_hash, vec![transcript(original_hash, 9)])]);
        let replacement =
            BTreeMap::from([(replacement_hash, vec![transcript(replacement_hash, 10)])]);
        synchronize_fastpq_transcripts(&original);
        let overlay = begin_exec_witness_overlay();
        synchronize_fastpq_transcripts(&replacement);
        if commit {
            overlay.commit();
        } else {
            drop(overlay);
        }
        let expected = if commit { replacement } else { original };
        let witness = drain_exec_witness_checked(|raw| {
            assert_eq!(raw, &expected);
            Ok(())
        })
        .unwrap();
        assert_eq!(witness.fastpq_transcripts, map_to_bundles(expected));
    }
}

#[test]
fn legacy_drain_retains_digest_finalization_for_cleanup_callers() {
    let _guard = exec_witness_guard();
    start_block();
    let hash = Hash::new(b"legacy finalization remains unchanged");
    let expected = transcript(hash, 11);
    let mut raw = expected.clone();
    raw.poseidon_preimage_digest = None;
    record_fastpq_transcript(&raw);
    let witness = drain_exec_witness();
    assert_eq!(witness.fastpq_transcripts[0].transcripts, vec![expected]);
}

#[test]
fn checked_first_capture_requires_active_recorder_including_empty_sources() {
    let _guard = exec_witness_guard();
    clear_block();
    let mut calls = 0;
    let error = drain_exec_witness_checked(|_| {
        calls += 1;
        Ok(())
    })
    .unwrap_err();
    assert!(error.contains("no active global recorder"));
    assert_eq!(calls, 0);
    assert_inactive_empty();
    start_block();
    let empty = drain_exec_witness_checked(|raw| {
        calls += 1;
        assert!(raw.is_empty());
        Ok(())
    })
    .unwrap();
    assert_eq!(calls, 1);
    assert!(empty.reads.is_empty());
    assert!(empty.writes.is_empty());
    assert!(empty.fastpq_transcripts.is_empty());
    assert!(empty.fastpq_batches.is_empty());
    assert_inactive_empty();
    assert!(
        drain_exec_witness_checked(|_| {
            panic!("a drained recorder cannot become a new empty first capture")
        })
        .is_err()
    );
    finish_cached_exec_witness_capture().unwrap();
}

#[test]
fn cached_finish_accepts_only_inactive_empty_recorder() {
    let _guard = exec_witness_guard();
    clear_block();
    finish_cached_exec_witness_capture().unwrap();
    for mutation in 0..5 {
        {
            let mut g = lock_slot();
            match mutation {
                0 => g.active = true,
                1 => {
                    g.reads.insert(vec![1], vec![10]);
                }
                2 => {
                    g.writes.insert(vec![2], vec![20]);
                }
                3 => {
                    g.fastpq_transcripts
                        .insert(Hash::new(b"unexpected empty bundle"), Vec::new());
                }
                4 => {
                    g.active = true;
                    let hash = Hash::new(b"unexpected cached source");
                    g.fastpq_transcripts
                        .insert(hash, vec![transcript(hash, 12)]);
                }
                _ => unreachable!(),
            }
        }
        assert!(
            finish_cached_exec_witness_capture().is_err(),
            "mutation {mutation}"
        );
        assert_inactive_empty();
        finish_cached_exec_witness_capture().unwrap();
    }
}

#[test]
fn cached_finish_rejects_overlay_even_after_first_drain_rejection_deactivates_slot() {
    let _guard = exec_witness_guard();
    for commit in [false, true] {
        start_block();
        let overlay = begin_exec_witness_overlay();
        record_marker();
        assert!(
            drain_exec_witness_checked(|_| {
                panic!("unfinished overlay cannot be validated as a final global witness")
            })
            .is_err()
        );
        assert_inactive_empty();
        let error = finish_cached_exec_witness_capture().unwrap_err();
        assert!(error.contains("pending current-thread overlay"));
        if commit {
            overlay.commit();
        } else {
            drop(overlay);
        }
        assert_inactive_empty();
        finish_cached_exec_witness_capture().unwrap();
    }
}

#[test]
fn caught_validator_panic_discards_capture_before_the_exclusive_guard_is_dropped() {
    let _guard = exec_witness_guard();
    start_block();
    record_marker();
    let hash = Hash::new(b"checked validator panic");
    let original = BTreeMap::from([(hash, vec![transcript(hash, 19)])]);
    synchronize_fastpq_transcripts(&original);
    let panic = std::panic::catch_unwind(|| {
        let _ = drain_exec_witness_checked(|raw| {
            assert_eq!(raw, &original);
            panic!("validator panic must discard the active capture");
        });
    });
    assert!(panic.is_err());
    assert_inactive_empty();
    {
        let g = lock_slot();
        assert!(g.generation.is_none());
    }
    // The outer exclusive guard is deliberately still held. Neither writes nor
    // resynchronization can repair the failed window or create a new first capture.
    record_marker();
    synchronize_fastpq_transcripts(&original);
    assert_eq!(
        drain_exec_witness_checked(|_| panic!("inactive capture must reject before validation")),
        Err("ordinary witness capture has no active global recorder".to_owned()),
    );
    assert_inactive_empty();
    start_block();
    record_marker();
    synchronize_fastpq_transcripts(&original);
    let fresh = drain_exec_witness_checked(|raw| {
        assert_eq!(raw, &original);
        Ok(())
    })
    .unwrap();
    assert_eq!(fresh.fastpq_transcripts, map_to_bundles(original));
    assert_eq!(fresh.reads.len(), 2);
    assert_eq!(fresh.writes.len(), 2);
    assert_inactive_empty();
}
