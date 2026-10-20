// Exact paired deltas under the existing original membership publication owner.

fn apply_delta(map: &mut BTreeMap<Key, u64>, key: &Key, before: Option<u64>, after: Option<u64>) {
    assert_eq!(
        map.get(key).copied(),
        before,
        "original membership preimage"
    );
    match after {
        Some(value) => {
            map.insert(*key, value);
        }
        None => {
            map.remove(key);
        }
    }
}

#[test]
fn paired_publication_delta_recreates_exact_advance_replace_repeat_and_empty_cuts() {
    use crate::state::storage_transactions::TransactionsBlockField;
    let [old, reused, tip_only, next] = [
        key(b"delta-old"),
        key(b"delta-reused"),
        key(b"delta-tip"),
        key(b"delta-next"),
    ];
    for mode in 0..6 {
        let storage = TransactionsStorage::new();
        if mode != 4 {
            commit(&storage, &[old, reused], 1);
            commit(&storage, &[reused, tip_only], 2);
        }
        let mut before = capture(&storage.block(), usize::MAX);
        let replacement = mode == 1 || mode == 3;
        let original = if replacement {
            storage.block_and_revert()
        } else {
            storage.block()
        };
        let mut field = TransactionsBlockField::new(original);
        let (keys, frontier) = match mode {
            0 => (vec![next], 3),
            1 => (vec![next], 2),
            2 => (vec![reused, tip_only], 2),
            3 => (vec![], 2),
            4 => (vec![], 1),
            _ => (vec![], 3),
        };
        field.insert_block(keys.into_iter().collect(), height(frontier));
        field.try_prepare_publication().unwrap();
        let writer = field.prepared_membership_writer().unwrap();
        let surface = writer.publication_surface();
        let delta = writer
            .membership_publication_delta(&surface, usize::MAX)
            .unwrap();
        assert_eq!(delta.base().surface(), &surface);
        assert_eq!(delta.base().committed_frontier(), before.frontier);
        assert_eq!(
            delta.base().logical_predecessor_frontier(),
            before.frontier - u64::from(replacement)
        );
        assert_eq!(delta.base().successor_frontier(), frontier as u64);
        let full = capture_publication(writer, usize::MAX);
        let mut seen = BTreeSet::new();
        let mut rollback_rows = 0;
        delta
            .visit(|side, key, prior, after| {
                assert_ne!(prior, after);
                assert!(seen.insert((
                    usize::from(side == TransactionMembershipSide::Rollback),
                    *key
                )));
                match side {
                    TransactionMembershipSide::Current => {
                        apply_delta(&mut before.current, key, prior, after)
                    }
                    TransactionMembershipSide::Rollback => {
                        rollback_rows += 1;
                        apply_delta(&mut before.rollback, key, prior, after);
                    }
                }
                Ok::<_, Infallible>(())
            })
            .unwrap();
        assert_eq!(
            (before.current, before.rollback),
            (full.current.clone(), full.rollback.clone()),
            "original rollback delta must recreate exact successor pair"
        );
        assert_eq!(rollback_rows, if mode == 0 || mode == 5 { 2 } else { 0 });
        drop(delta);
        field.try_prepare_physical().unwrap();
        field.publish_prepared();
        field.release_writers();
        drop(field);
        let published = capture(&storage.block(), usize::MAX);
        assert_eq!(full.current, published.current);
        assert_eq!(full.rollback, published.rollback);
    }
}

#[test]
fn paired_publication_delta_requires_exact_original_surface_before_visitation() {
    use crate::state::storage_transactions::TransactionsBlockField;
    let storage = TransactionsStorage::new();
    commit(&storage, &[key(b"base-old")], 1);
    let staged = key(b"base-staged");
    let retired = {
        let mut field = TransactionsBlockField::new(storage.block());
        field.insert_block(BTreeSet::from([staged]), height(2));
        field.try_prepare_publication().unwrap();
        field
            .prepared_membership_writer()
            .unwrap()
            .publication_surface()
    };
    let mut field = TransactionsBlockField::new(storage.block());
    field.insert_block(BTreeSet::from([staged]), height(2));
    field.try_prepare_publication().unwrap();
    let writer = field.prepared_membership_writer().unwrap();
    let original = writer.publication_surface();
    assert_ne!(
        original, retired,
        "equal rows do not replace original staging allocation"
    );
    let foreign_storage = TransactionsStorage::new();
    let foreign = foreign_storage.block().publication_surface();
    for changed in [&retired, &foreign] {
        assert!(
            matches!(
                writer.membership_publication_delta(changed, usize::MAX),
                Err(TransactionMembershipAuthorityError::ChangedPublicationBase)
            ),
            "membership delta must reject a substituted original publication surface"
        );
    }
    assert!(matches!(
        writer.membership_publication_delta(&original, 1),
        Err(TransactionMembershipAuthorityError::TraversalRefused {
            required: 2,
            limit: 1
        })
    ));
    let source = writer.membership_publication_delta(&original, 2).unwrap();
    assert_eq!(source.row_visits(), 2);
    assert_eq!(source.base().surface(), &original);
}

#[test]
fn paired_delta_work_is_independent_of_history_and_consumer_refusal_retries_original() {
    use crate::state::storage_transactions::TransactionsBlockField;
    let storage = TransactionsStorage::new();
    for at in 1..=128 {
        let member = HashOf::from_untyped_unchecked(Hash::new((at as u64).to_le_bytes()));
        commit(&storage, &[member], at);
    }
    let mut field = TransactionsBlockField::new(storage.block());
    field.insert_block(BTreeSet::from([key(b"bounded-delta")]), height(129));
    field.try_prepare_publication().unwrap();
    let writer = field.prepared_membership_writer().unwrap();
    let original = writer.publication_surface();
    assert!(writer.membership_publication_authority_cut(2).is_err());
    let source = writer.membership_publication_delta(&original, 2).unwrap();
    assert_eq!(source.row_visits(), 2);
    let reserved = storage.budget.reserved_bytes();
    for failure_side in [
        TransactionMembershipSide::Current,
        TransactionMembershipSide::Rollback,
    ] {
        let mut failed = false;
        let result = source.visit(|side, _, _, _| {
            assert!(!failed, "no callback after original consumer refusal");
            if side == failure_side {
                failed = true;
                Err("retained exact consumer cause")
            } else {
                Ok(())
            }
        });
        assert_eq!(
            result,
            Err(TransactionMembershipVisitError::Consumer(
                "retained exact consumer cause"
            ))
        );
        assert!(failed);
        assert_eq!(writer.publication_surface(), original);
        assert_eq!(
            storage.budget.reserved_bytes(),
            reserved,
            "borrowed delta allocates no graph"
        );
    }
    let mut rows = 0;
    source
        .visit(|_, _, _, _| {
            rows += 1;
            Ok::<_, Infallible>(())
        })
        .unwrap();
    assert_eq!(rows, 2);
    assert_eq!(storage.budget.reserved_bytes(), reserved);
}
