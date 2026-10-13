//! Computed-only reuse, owner isolation, bounded metadata and cancellation.

use super::*;
use ff::Field;
use iroha_pasta::{Ep, Eq};

use crate::pcs::ipa::commit::{
    Secrecy, commit_lagrange_cancellable, test_observation::CommitmentProbe,
};

fn reuse<C: PastaCurve>() {
    let params = PinnedParams::<C>::derive(4).unwrap();
    let independent = PinnedParams::<C>::derive(4).unwrap();
    let cloned = params.clone();
    let mut values = vec![C::ScalarExt::ZERO; 16];
    values[0] = C::ScalarExt::from(7);
    let expected = commit_lagrange_cancellable(
        params.params(),
        &values,
        &C::ScalarExt::from(DEFAULT_BLIND),
        Secrecy::Public,
        MemoryBudget::DEFAULT,
        None,
    )
    .unwrap()
    .to_affine();
    let probe = CommitmentProbe::start();
    assert_eq!(
        params
            .commit_public_column_cancellable(&values, MemoryBudget::DEFAULT, None)
            .unwrap(),
        expected
    );
    assert_eq!(probe.calls(), 1);
    assert_eq!(
        cloned
            .commit_public_column_cancellable(&values, MemoryBudget::DEFAULT, None)
            .unwrap(),
        expected
    );
    assert_eq!(probe.calls(), 1, "cloned owners reuse the computed point");
    assert_eq!(params, independent, "cache state is not parameter identity");
    assert_eq!(
        independent
            .commit_public_column_cancellable(&values, MemoryBudget::DEFAULT, None)
            .unwrap(),
        expected
    );
    assert_eq!(
        probe.calls(),
        2,
        "equal independently admitted parameters own separate caches"
    );
    values[0] += C::ScalarExt::ONE;
    let changed = params
        .commit_public_column_cancellable(&values, MemoryBudget::DEFAULT, None)
        .unwrap();
    assert_ne!(changed, expected);
    assert_eq!(
        probe.calls(),
        3,
        "changed scalar cannot reuse a prior point"
    );
    values.swap(0, 1);
    assert_ne!(
        params
            .commit_public_column_cancellable(&values, MemoryBudget::DEFAULT, None)
            .unwrap(),
        changed
    );
    assert_eq!(probe.calls(), 4, "row order is committed");
    let shortened = params
        .commit_public_column_cancellable(&values[..8], MemoryBudget::DEFAULT, None)
        .unwrap();
    assert_eq!(
        probe.calls(),
        5,
        "row count is domain separated even with zero padding"
    );
    assert_eq!(
        params
            .commit_public_column_cancellable(&values[..8], MemoryBudget::DEFAULT, None)
            .unwrap(),
        shortened
    );
    assert_eq!(probe.calls(), 5);
}

#[test]
fn computed_points_reuse_only_identical_columns_and_cloned_owners() {
    reuse::<Ep>();
    reuse::<Eq>();
}

#[test]
fn curve_and_parameter_domains_have_independent_caches() {
    let pallas_small = PinnedParams::<Ep>::derive(3).unwrap();
    let pallas_large = PinnedParams::<Ep>::derive(4).unwrap();
    let vesta = PinnedParams::<Eq>::derive(3).unwrap();
    let pallas_values = [<Ep as PastaCurve>::ScalarExt::ONE; 8];
    let vesta_values = [<Eq as PastaCurve>::ScalarExt::ONE; 8];
    let probe = CommitmentProbe::start();
    let small = pallas_small
        .commit_public_column_cancellable(&pallas_values, MemoryBudget::DEFAULT, None)
        .unwrap();
    let large = pallas_large
        .commit_public_column_cancellable(&pallas_values, MemoryBudget::DEFAULT, None)
        .unwrap();
    assert_ne!(small, large);
    let other_curve = vesta
        .commit_public_column_cancellable(&vesta_values, MemoryBudget::DEFAULT, None)
        .unwrap();
    assert_eq!(probe.calls(), 3);
    assert_eq!(
        pallas_small
            .commit_public_column_cancellable(&pallas_values, MemoryBudget::DEFAULT, None)
            .unwrap(),
        small
    );
    assert_eq!(
        pallas_large
            .commit_public_column_cancellable(&pallas_values, MemoryBudget::DEFAULT, None)
            .unwrap(),
        large
    );
    assert_eq!(
        vesta
            .commit_public_column_cancellable(&vesta_values, MemoryBudget::DEFAULT, None)
            .unwrap(),
        other_curve
    );
    assert_eq!(probe.calls(), 3);
}

#[test]
fn cache_capacity_is_fixed_and_duplicate_insertions_do_not_evict() {
    let params = PinnedParams::<Ep>::derive(2).unwrap();
    let computed = params
        .commit_public_column_cancellable(&[], MemoryBudget::DEFAULT, None)
        .unwrap();
    let mut cache = PublicColumnCache::<Ep>::default();
    // Exercise only the bounded FIFO container here; actual computed-point
    // population and key separation are covered through the owner API above.
    let key = |index: usize| {
        let mut digest = [0; 32];
        digest[..8].copy_from_slice(&(index as u64).to_le_bytes());
        digest
    };
    for index in 0..MAX_COLUMNS {
        cache.insert(key(index), computed);
    }
    assert_eq!(cache.points.len(), MAX_COLUMNS);
    assert_eq!(cache.order.len(), MAX_COLUMNS);
    cache.insert(key(MAX_COLUMNS - 1), computed);
    assert!(cache.points.contains_key(&key(0)));
    assert_eq!(cache.order.len(), MAX_COLUMNS);
    cache.insert(key(MAX_COLUMNS), computed);
    assert!(!cache.points.contains_key(&key(0)));
    assert!(cache.points.contains_key(&key(1)));
    assert!(cache.points.contains_key(&key(MAX_COLUMNS)));
    assert_eq!(cache.points.len(), MAX_COLUMNS);
    assert_eq!(cache.order.len(), MAX_COLUMNS);
}

#[test]
fn cancelled_hits_and_misses_return_no_point_and_poison_recomputes() {
    let params = PinnedParams::<Ep>::derive(3).unwrap();
    let values = [<Ep as PastaCurve>::ScalarExt::ONE; 8];
    let expected = params
        .commit_public_column_cancellable(&values, MemoryBudget::DEFAULT, None)
        .unwrap();
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    let probe = CommitmentProbe::start();
    for column in [&values[..], &values[..4]] {
        assert_eq!(
            params.commit_public_column_cancellable(
                column,
                MemoryBudget::DEFAULT,
                Some(&cancelled)
            ),
            Err(MsmError::Cancelled)
        );
    }
    assert_eq!(probe.calls(), 0);
    assert_eq!(params.public_columns.lock().unwrap().points.len(), 1);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = params.public_columns.lock().unwrap();
            panic!("deliberately poison optional performance cache");
        }))
        .is_err()
    );
    for expected_calls in 1..=2 {
        assert_eq!(
            params
                .commit_public_column_cancellable(&values, MemoryBudget::DEFAULT, None)
                .unwrap(),
            expected
        );
        assert_eq!(
            probe.calls(),
            expected_calls,
            "poisoned state is never used"
        );
    }
}

#[test]
fn oversized_columns_fail_before_hash_or_msm() {
    let params = PinnedParams::<Ep>::derive(2).unwrap();
    let values = [<Ep as PastaCurve>::ScalarExt::ZERO; 5];
    let probe = CommitmentProbe::start();
    assert_eq!(
        params.commit_public_column_cancellable(&values, MemoryBudget::DEFAULT, None),
        Err(MsmError::LengthMismatch(iroha_pasta::LengthMismatch {
            left: 5,
            right: 4
        }))
    );
    assert_eq!(probe.calls(), 0);
    assert!(params.public_columns.lock().unwrap().points.is_empty());
}

fn fused_handle<C: PastaCurve>() {
    let owner = PinnedParams::<C>::derive(11).unwrap();
    let independent = PinnedParams::<C>::derive(11).unwrap();
    let other_domain = PinnedParams::<C>::derive(12).unwrap();
    let values: Vec<_> = (0..1025)
        .map(|row| match row % 3 {
            0 => C::ScalarExt::ZERO,
            1 => -C::ScalarExt::ONE,
            _ => C::ScalarExt::from(row as u64),
        })
        .collect();
    for length in [0, 1, 16, 256, 1024, 1025] {
        let values = &values[..length];
        let mut streamed = Vec::new();
        let column = HashedPublicColumn::with_canonical_sink(
            values,
            |bytes| streamed.extend_from_slice(bytes),
            None,
        )
        .unwrap();
        let canonical: Vec<_> = values
            .iter()
            .flat_map(|value| value.to_repr().as_ref().to_vec())
            .collect();
        assert_eq!(streamed, canonical);
        // Independent old framing, not the constructor reused as a reference.
        let mut expected_hash = Sha256::new();
        expected_hash.update(COLUMN_DOMAIN);
        expected_hash.update(DEFAULT_BLIND.to_le_bytes());
        expected_hash.update((values.len() as u64).to_le_bytes());
        expected_hash.update(&canonical);
        assert_eq!(column.digest, <[u8; 32]>::from(expected_hash.finalize()));
        let expected = commit_lagrange_cancellable(
            owner.params(),
            values,
            &C::ScalarExt::from(DEFAULT_BLIND),
            Secrecy::Public,
            MemoryBudget::DEFAULT,
            None,
        )
        .unwrap()
        .to_affine();
        let probe = CommitmentProbe::start();
        assert_eq!(
            owner
                .commit_hashed_public_column_cancellable(&column, MemoryBudget::DEFAULT, None)
                .unwrap(),
            expected
        );
        assert_eq!(
            owner
                .clone()
                .commit_hashed_public_column_cancellable(&column, MemoryBudget::DEFAULT, None)
                .unwrap(),
            expected
        );
        assert_eq!(probe.calls(), 1);
        assert_eq!(
            independent
                .commit_hashed_public_column_cancellable(&column, MemoryBudget::DEFAULT, None)
                .unwrap(),
            expected
        );
        assert_eq!(
            probe.calls(),
            2,
            "a handle never supplies another owner's point"
        );
        let other = other_domain
            .commit_hashed_public_column_cancellable(&column, MemoryBudget::DEFAULT, None)
            .unwrap();
        assert_eq!(
            other,
            commit_lagrange_cancellable(
                other_domain.params(),
                values,
                &C::ScalarExt::from(DEFAULT_BLIND),
                Secrecy::Public,
                MemoryBudget::DEFAULT,
                None
            )
            .unwrap()
            .to_affine()
        );
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert_eq!(
            owner.commit_hashed_public_column_cancellable(
                &column,
                MemoryBudget::DEFAULT,
                Some(&cancelled)
            ),
            Err(MsmError::Cancelled)
        );
    }
    let cancelled = CancellationToken::new();
    let mut calls = 0;
    assert!(matches!(
        HashedPublicColumn::with_canonical_sink(
            &values,
            |_| {
                calls += 1;
                if calls == 1 {
                    cancelled.cancel();
                }
            },
            Some(&cancelled)
        ),
        Err(MsmError::Cancelled)
    ));
    assert_eq!(
        calls, 1024,
        "streaming cancellation checked at the next bounded chunk"
    );
    assert!(matches!(
        HashedPublicColumn::with_canonical_sink(
            &values,
            |_| panic!("pre-cancelled hashing reached the scalar stream"),
            Some(&cancelled)
        ),
        Err(MsmError::Cancelled)
    ));
    let short = PinnedParams::<C>::derive(4).unwrap();
    let column = HashedPublicColumn::with_canonical_sink(&values, |_| {}, None).unwrap();
    assert!(matches!(
        short.commit_hashed_public_column_cancellable(&column, MemoryBudget::DEFAULT, None),
        Err(MsmError::LengthMismatch(_))
    ));
    assert!(short.public_columns.lock().unwrap().points.is_empty());
}

#[test]
fn fused_native_handles_preserve_streams_owner_binding_and_cancellation_on_both_curves() {
    fused_handle::<Ep>();
    fused_handle::<Eq>();
}
