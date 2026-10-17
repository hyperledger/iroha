//! Admitted-graph memo semantics over DATA entries. No installation, owner, provider,
//! custody root or key is constructed here, and no entry carries authority.
use super::*;
use std::sync::{
    Barrier,
    atomic::{AtomicUsize, Ordering},
};

fn originals() -> [Vec<u8>; 8] {
    [
        b"app manifest".to_vec(),
        b"envelope".to_vec(),
        b"wallet runtime".to_vec(),
        b"verifier pack".to_vec(),
        b"producer inventory".to_vec(),
        b"signed genesis".to_vec(),
        b"/carrier/root".to_vec(),
        Vec::new(),
    ]
}
fn key(originals: &[Vec<u8>; 8], root: iroha_fs::FileIdentity) -> MemoKey {
    MemoKey::new(
        &RuntimeOriginals {
            app_manifest: &originals[0],
            envelope: &originals[1],
            wallet_runtime: &originals[2],
            verifier_pack: &originals[3],
            producer_inventory: &originals[4],
            signed_genesis: &originals[5],
            originals_root: &originals[6],
            registration_source: &originals[7],
        },
        root,
    )
}
/// Two distinct live directory identities.
fn roots() -> (
    tempfile::TempDir,
    iroha_fs::FileIdentity,
    iroha_fs::FileIdentity,
) {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path().canonicalize().unwrap();
    let identity = |name: &str| {
        iroha_fs::PrivateDirectory::open_or_create(base.join(name))
            .unwrap()
            .identity()
            .unwrap()
    };
    let (first, second) = (identity("first"), identity("second"));
    assert_ne!(first, second);
    (temp, first, second)
}
fn store(memo: &Memo<Arc<u8>>, key: MemoKey, value: &Arc<u8>) {
    let stored = memo.settle(Ok(((), (key, Arc::clone(value)))));
    assert_eq!(stored, Ok(()));
}
fn hit(memo: &Memo<Arc<u8>>, key: &MemoKey) -> Option<Arc<u8>> {
    memo.reuse(key, Ok)
}

#[test]
fn key_binds_every_exact_original_its_framing_and_the_root_identity() {
    let (_temp, root, other) = roots();
    let base = originals();
    assert!(key(&base, root) == key(&base, root));
    assert!(key(&base, root) != key(&base, other));
    for field in 0..8 {
        let mut changed = base.clone();
        match changed[field].first_mut() {
            Some(byte) => *byte ^= 1,
            None => changed[field].push(0),
        }
        let (original, mutated) = (key(&base, root), key(&changed, root));
        assert!(original != mutated, "field {field}");
        assert_ne!(original.digest, mutated.digest, "field {field}");
        // Moving one byte across a field boundary is also another key.
        if field < 7 {
            let mut moved = base.clone();
            if let Some(byte) = moved[field].pop() {
                moved[field + 1].insert(0, byte);
                assert!(key(&base, root) != key(&moved, root), "field {field}");
            }
        }
    }
    // An equal digest alone never selects an entry: the exact frame is compared too.
    let genuine = key(&base, root);
    let forged = MemoKey {
        digest: genuine.digest,
        frame: b"another frame".to_vec().into_boxed_slice(),
    };
    assert!(genuine != forged);
    let memo = Memo::new();
    store(&memo, key(&base, root), &Arc::new(1));
    assert!(hit(&memo, &forged).is_none());
    // The mismatched lookup evicted the entry before any fresh admission could run.
    assert!(hit(&memo, &genuine).is_none());
}

#[test]
fn hit_returns_the_stored_graph_and_a_mismatch_evicts_without_reuse() {
    let (_temp, root, other) = roots();
    let base = originals();
    let memo = Memo::new();
    let admitted = Arc::new(7);
    store(&memo, key(&base, root), &admitted);
    // A hit hands out the SAME admitted objects; nothing is rebuilt or copied.
    let reused = hit(&memo, &key(&base, root)).unwrap();
    assert!(Arc::ptr_eq(&reused, &admitted));
    drop(reused);
    // A different carrier root misses before its reuse check can run, and evicts.
    let mut called = false;
    assert!(
        memo.reuse(&key(&base, other), |_| {
            called = true;
            Ok(())
        })
        .is_none()
    );
    assert!(!called);
    assert_eq!(Arc::strong_count(&admitted), 1);
    assert!(hit(&memo, &key(&base, root)).is_none());
}

#[test]
fn refused_reuse_evicts_and_keeps_an_entry_stored_meanwhile() {
    let (_temp, root, _) = roots();
    let base = originals();
    let memo = Memo::new();
    let first = Arc::new(1);
    store(&memo, key(&base, root), &first);
    // A failed revalidation is a miss: the entry is gone before re-admission.
    assert!(
        memo.reuse(&key(&base, root), |_| -> Result<()> {
            Err(Failure::code(INVALID))
        })
        .is_none()
    );
    assert_eq!(Arc::strong_count(&first), 1);
    assert!(hit(&memo, &key(&base, root)).is_none());
    // The check runs outside the lock; a concurrent attempt may store a fresh graph
    // meanwhile, and refusing the older one must not evict it.
    store(&memo, key(&base, root), &first);
    let fresh = Arc::new(2);
    assert!(
        memo.reuse(&key(&base, root), |_| -> Result<()> {
            store(&memo, key(&base, root), &fresh);
            Err(Failure::code(CUSTODY_LOST))
        })
        .is_none()
    );
    assert!(Arc::ptr_eq(&hit(&memo, &key(&base, root)).unwrap(), &fresh));
    assert_eq!(Arc::strong_count(&first), 1);
}

#[test]
fn settle_stores_only_complete_success_and_evicts_on_invalid_or_custody_loss() {
    let (_temp, root, other) = roots();
    let base = originals();
    let memo = Memo::new();
    let admitted = Arc::new(3);
    store(&memo, key(&base, root), &admitted);
    for status in [
        UNAVAILABLE,
        RESOURCE,
        ARTIFACTS_UNAVAILABLE,
        CANCELLED,
        NOT_ENOUGH_MEMORY,
    ] {
        let refused: Result<()> = memo.settle(Err(Failure::code(status)));
        assert_eq!(refused, Err(Failure::code(status)));
        assert!(hit(&memo, &key(&base, root)).is_some(), "status {status}");
    }
    for status in [INVALID, CUSTODY_LOST] {
        store(&memo, key(&base, root), &admitted);
        let refused: Result<()> = memo.settle(Err(Failure::code(status)));
        assert_eq!(refused, Err(Failure::code(status)));
        assert!(hit(&memo, &key(&base, root)).is_none(), "status {status}");
        assert_eq!(Arc::strong_count(&admitted), 1);
    }
    // Success passes its value through and stores the one entry, replacing any other.
    let replaced = Arc::new(4);
    store(&memo, key(&base, other), &replaced);
    assert_eq!(
        memo.settle(Ok((9_u32, (key(&base, root), Arc::clone(&admitted))))),
        Ok(9)
    );
    assert_eq!(Arc::strong_count(&replaced), 1);
    assert!(hit(&memo, &key(&base, other)).is_none());
}

#[test]
fn one_entry_bound_drops_the_previous_graph_on_replacement() {
    let (_temp, root, other) = roots();
    let base = originals();
    let memo = Memo::new();
    let first = Arc::new(1);
    let second = Arc::new(2);
    store(&memo, key(&base, root), &first);
    store(&memo, key(&base, other), &second);
    assert_eq!(Arc::strong_count(&first), 1);
    assert!(Arc::ptr_eq(
        &hit(&memo, &key(&base, other)).unwrap(),
        &second
    ));
    // Same key, newer graph: the older one is released, not kept beside it.
    let third = Arc::new(3);
    store(&memo, key(&base, other), &third);
    assert_eq!(Arc::strong_count(&second), 1);
    assert!(Arc::ptr_eq(
        &hit(&memo, &key(&base, other)).unwrap(),
        &third
    ));
}

/// DATA entry whose clone can panic while the memo lock is held.
struct Fragile {
    panic: bool,
    token: Arc<()>,
}
impl Clone for Fragile {
    fn clone(&self) -> Self {
        assert!(!self.panic, "DATA clone panic under the memo lock");
        Self {
            panic: self.panic,
            token: Arc::clone(&self.token),
        }
    }
}

#[test]
fn poisoned_memo_is_a_miss_that_discards_its_entry_and_recovers() {
    let (_temp, root, _) = roots();
    let base = originals();
    let memo = Memo::new();
    let token = Arc::new(());
    let stored: Result<()> = memo.settle(Ok((
        (),
        (
            key(&base, root),
            Fragile {
                panic: true,
                token: Arc::clone(&token),
            },
        ),
    )));
    stored.unwrap();
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        memo.reuse(&key(&base, root), |_| Ok(()))
    }));
    assert!(panicked.is_err());
    assert!(memo.slot.is_poisoned());
    // The poisoned entry is never handed out; it is discarded and the lock recovers.
    assert!(memo.reuse(&key(&base, root), |_| Ok(())).is_none());
    assert!(!memo.slot.is_poisoned());
    assert_eq!(Arc::strong_count(&token), 1);
    let stored: Result<()> = memo.settle(Ok((
        (),
        (
            key(&base, root),
            Fragile {
                panic: false,
                token: Arc::clone(&token),
            },
        ),
    )));
    stored.unwrap();
    assert!(memo.reuse(&key(&base, root), |_| Ok(())).is_some());
}

/// DATA entry that records whether the memo lock was free when it was dropped.
struct Probe {
    panic: bool,
}
/// The only memo holding `Probe` entries.
static PROBED: Memo<Probe> = Memo::new();
/// `Probe` drops: `[after the lock was released, while it was held]`.
static PROBE_DROPS: [AtomicUsize; 2] = [AtomicUsize::new(0), AtomicUsize::new(0)];
impl Clone for Probe {
    fn clone(&self) -> Self {
        assert!(!self.panic, "DATA clone panic under the memo lock");
        Self { panic: self.panic }
    }
}
impl Drop for Probe {
    fn drop(&mut self) {
        // `try_lock` fails while any guard is held, including one held by this thread.
        let locked = usize::from(PROBED.slot.try_lock().is_err());
        PROBE_DROPS[locked].fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn replaced_evicted_and_discarded_entries_are_dropped_after_the_lock_is_released() {
    let (_temp, root, other) = roots();
    let base = originals();
    let admit = |identity, panic| {
        let stored: Result<()> = PROBED.settle(Ok(((), (key(&base, identity), Probe { panic }))));
        stored.unwrap();
    };
    // Replaced by a newer complete success.
    admit(root, false);
    admit(other, false);
    // Evicted by a lookup under another key, before any reuse check runs.
    assert!(PROBED.reuse(&key(&base, root), |_| Ok(())).is_none());
    // Evicted after a refused reuse; the refusing check drops its own clone.
    admit(root, false);
    assert!(
        PROBED
            .reuse(&key(&base, root), |_| -> Result<()> {
                Err(Failure::code(INVALID))
            })
            .is_none()
    );
    // Evicted by an INVALID attempt.
    admit(root, false);
    let refused: Result<()> = PROBED.settle(Err(Failure::code(INVALID)));
    assert_eq!(refused, Err(Failure::code(INVALID)));
    // Discarded with a poisoned lock.
    admit(root, true);
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        PROBED.reuse(&key(&base, root), |_| Ok(()))
    }));
    assert!(panicked.is_err());
    assert!(PROBED.slot.is_poisoned());
    assert!(PROBED.reuse(&key(&base, root), |_| Ok(())).is_none());
    assert!(!PROBED.slot.is_poisoned());
    // Five entries and one clone were dropped, none of them under the memo lock.
    assert_eq!(PROBE_DROPS[1].load(Ordering::SeqCst), 0);
    assert_eq!(PROBE_DROPS[0].load(Ordering::SeqCst), 6);
}

#[test]
fn concurrent_attempts_only_ever_reuse_the_graph_of_their_exact_key() {
    let (_temp, root, other) = roots();
    let memo = Memo::<Arc<u8>>::new();
    let threads = 8;
    let start = Barrier::new(threads);
    std::thread::scope(|scope| {
        for thread in 0..threads {
            let (memo, start) = (&memo, &start);
            scope.spawn(move || {
                let base = originals();
                // Even threads open one carrier root, odd threads another.
                let (identity, tag) = if thread % 2 == 0 {
                    (root, 0)
                } else {
                    (other, 1)
                };
                start.wait();
                for round in 0..200 {
                    let attempt = key(&base, identity);
                    let reused = memo.reuse(&attempt, |value: Arc<u8>| {
                        if round % 7 == 0 {
                            // An occasional failed revalidation.
                            return Err(Failure::code(INVALID));
                        }
                        Ok(value)
                    });
                    match reused {
                        Some(value) => assert_eq!(*value, tag),
                        // A miss re-admits and settles its own complete success.
                        None => memo.settle(Ok(((), (attempt, Arc::new(tag))))).unwrap(),
                    }
                }
            });
        }
    });
    // The one slot holds nothing, or one thread's graph under exactly that thread's key.
    let base = originals();
    let slot = memo.slot.lock().unwrap();
    if let Some((stored, value)) = &slot.entry {
        let tag = [(root, 0), (other, 1)]
            .into_iter()
            .find(|(identity, _)| *stored == key(&base, *identity))
            .map(|(_, tag)| tag);
        assert_eq!(tag, Some(**value));
    }
}
