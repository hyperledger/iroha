//! Exact arithmetic, bounded ownership and fail-closed partial-MSM reuse.

use super::*;
use ff::Field;
use group::{Curve, Group};
use iroha_pasta::{Ep, Eq};

use crate::pcs::ipa::commit::{
    Secrecy, commit_lagrange_cancellable, test_observation::CommitmentProbe,
};

fn reference<C: PastaCurve>(owner: &PinnedParams<C>, values: &[C::ScalarExt]) -> C::AffineExt {
    commit_lagrange_cancellable(
        owner.params(),
        values,
        &C::ScalarExt::from(DEFAULT_BLIND),
        Secrecy::Public,
        MemoryBudget::DEFAULT,
        None,
    )
    .unwrap()
    .to_affine()
}

fn arithmetic<C: PastaCurve>() {
    let owner = PinnedParams::<C>::derive(12).unwrap();
    let mut values: Vec<_> = (0..4096)
        .map(|row| match row % 7 {
            0 => C::ScalarExt::ZERO,
            1 => -C::ScalarExt::ONE,
            _ => C::ScalarExt::from(row as u64 + 1),
        })
        .collect();
    for length in [0, 1, 8, 513, 1024, 1025, 2057, 4096] {
        let slice = &values[..length];
        let expected = reference(&owner, slice);
        assert_eq!(
            owner
                .commit_public_column_cancellable(slice, MemoryBudget::DEFAULT, None)
                .unwrap(),
            expected,
            "exact commitment at row count {length}"
        );
    }
    values.fill(C::ScalarExt::ZERO);
    let partial = CommitmentProbe::start_partial();
    for length in [0, 3, 1024, 1025, 4096] {
        let actual = owner
            .commit_public_column_cancellable(&values[..length], MemoryBudget::new(0), None)
            .unwrap();
        assert_eq!(actual, owner.params.w());
    }
    assert_eq!(partial.calls(), 0, "zero slices need no partial MSM");
}

#[test]
fn exact_commitments_cover_both_curves_block_boundaries_tails_and_zeros() {
    arithmetic::<Ep>();
    arithmetic::<Eq>();
}

fn reuse<C: PastaCurve>() {
    let owner = PinnedParams::<C>::derive(12).unwrap();
    let mut values = vec![C::ScalarExt::from(3); BLOCK_ROWS * 2 + 3];
    let full = CommitmentProbe::start();
    let partial = CommitmentProbe::start_partial();
    let first = owner
        .commit_public_column_cancellable(&values, MemoryBudget::DEFAULT, None)
        .unwrap();
    assert_eq!(full.calls(), 1);
    assert_eq!(partial.calls(), 3, "offset separates equal scalar blocks");
    assert_eq!(
        owner
            .clone()
            .commit_public_column_cancellable(&values, MemoryBudget::DEFAULT, None)
            .unwrap(),
        first
    );
    assert_eq!(full.calls(), 1);
    assert_eq!(
        partial.calls(),
        3,
        "whole-column hits perform no partial MSM"
    );
    values[BLOCK_ROWS + 7] += C::ScalarExt::ONE;
    let changed = owner
        .commit_public_column_cancellable(&values, MemoryBudget::DEFAULT, None)
        .unwrap();
    assert_ne!(changed, first);
    assert_eq!(full.calls(), 2);
    assert_eq!(
        partial.calls(),
        4,
        "unchanged partials survive a whole miss"
    );
    let independent = PinnedParams::<C>::derive(12).unwrap();
    assert_eq!(owner, independent);
    assert_eq!(
        independent
            .commit_public_column_cancellable(&values, MemoryBudget::DEFAULT, None)
            .unwrap(),
        changed
    );
    assert_eq!(
        partial.calls(),
        7,
        "independent owners do not share entries"
    );
    // Appending zero changes tail length, even when the committed point agrees.
    values.push(C::ScalarExt::ZERO);
    assert_eq!(
        owner
            .commit_public_column_cancellable(&values, MemoryBudget::DEFAULT, None)
            .unwrap(),
        changed
    );
    assert_eq!(partial.calls(), 8, "tail length is part of the digest");
    let short_owner = PinnedParams::<C>::derive(11).unwrap();
    short_owner
        .commit_public_column_cancellable(&values[..1024], MemoryBudget::DEFAULT, None)
        .unwrap();
    assert_eq!(partial.calls(), 9, "different domains do not share entries");
}

#[test]
fn only_exact_offset_length_scalars_and_cloned_parameter_owners_reuse_partials() {
    reuse::<Ep>();
    reuse::<Eq>();
}

#[test]
fn block_digests_bind_every_scalar_offset_and_length() {
    type F = <Ep as PastaCurve>::ScalarExt;
    let mut values = vec![F::ONE; BLOCK_ROWS];
    let first = block_digest(0, &values, None).unwrap();
    assert!(first.is_some());
    assert_ne!(first, block_digest(BLOCK_ROWS, &values, None).unwrap());
    assert_ne!(
        first,
        block_digest(0, &values[..BLOCK_ROWS - 1], None).unwrap()
    );
    values[BLOCK_ROWS - 1] += F::ONE;
    assert_ne!(first, block_digest(0, &values, None).unwrap());
    assert_eq!(block_digest(0, &vec![F::ZERO; BLOCK_ROWS], None), Ok(None));
    assert_eq!(block_digest::<F>(0, &[], None), Ok(None));
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    assert_eq!(
        block_digest(0, &values, Some(&cancelled)),
        Err(MsmError::Cancelled)
    );
}

#[test]
fn partial_fifo_is_bounded_and_hits_do_not_change_eviction_order() {
    let mut cache = PublicBlockCache::<Ep>::default();
    let key = |index: usize| {
        let mut bytes = [0; 32];
        bytes[..8].copy_from_slice(&(index as u64).to_le_bytes());
        bytes
    };
    for index in 0..MAX_BLOCKS {
        cache.insert(key(index), Ep::identity());
    }
    cache.insert(key(0), Ep::identity());
    assert_eq!(cache.order.len(), MAX_BLOCKS);
    assert_eq!(cache.points.len(), MAX_BLOCKS);
    cache.insert(key(MAX_BLOCKS), Ep::identity());
    assert!(!cache.points.contains_key(&key(0)));
    assert!(cache.points.contains_key(&key(1)));
    assert_eq!(cache.order.len(), MAX_BLOCKS);
    assert_eq!(cache.points.len(), MAX_BLOCKS);
}

#[test]
fn cancellation_bounds_and_poison_never_return_an_uncomputed_point() {
    type F = <Ep as PastaCurve>::ScalarExt;
    let owner = PinnedParams::<Ep>::derive(11).unwrap();
    let values = vec![F::ONE; 1025];
    let expected = owner
        .commit_public_column_cancellable(&values, MemoryBudget::DEFAULT, None)
        .unwrap();
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    let full = CommitmentProbe::start();
    let partial = CommitmentProbe::start_partial();
    for slice in [&values[..], &values[..1024]] {
        assert_eq!(
            owner.commit_public_column_cancellable(slice, MemoryBudget::DEFAULT, Some(&cancelled)),
            Err(MsmError::Cancelled)
        );
        assert_eq!(
            commit_column(
                &owner,
                slice,
                MemoryBudget::DEFAULT,
                &SharedMemoryBudget::process_default(),
                Some(&cancelled)
            ),
            Err(MsmError::Cancelled)
        );
    }
    assert_eq!(full.calls(), 0);
    assert_eq!(partial.calls(), 0);
    assert!(matches!(
        commit_column(
            &owner,
            &vec![F::ZERO; 2049],
            MemoryBudget::DEFAULT,
            &SharedMemoryBudget::process_default(),
            None
        ),
        Err(MsmError::LengthMismatch(_))
    ));
    assert_eq!(partial.calls(), 0);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = owner.public_columns.lock().unwrap();
            panic!("poison the optional whole/partial computation cache");
        }))
        .is_err()
    );
    for calls in [2, 4] {
        assert_eq!(
            owner
                .commit_public_column_cancellable(&values, MemoryBudget::DEFAULT, None)
                .unwrap(),
            expected
        );
        assert_eq!(partial.calls(), calls, "poisoned partials are recomputed");
    }
}

#[test]
fn scratch_budgets_and_shared_contention_preserve_exact_arithmetic() {
    type F = <Ep as PastaCurve>::ScalarExt;
    let owner = PinnedParams::<Ep>::derive(11).unwrap();
    let values = vec![F::from(7); 1025];
    let expected = reference(&owner, &values);
    let partial = CommitmentProbe::start_partial();
    assert!(matches!(
        owner.commit_public_column_cancellable(&values, MemoryBudget::new(0), None),
        Err(MsmError::Budget(_))
    ));
    assert_eq!(
        partial.calls(),
        2,
        "both joined workers observe the zero budget"
    );
    let cache = owner.public_columns.lock().unwrap();
    assert!(cache.points.is_empty());
    assert!(cache.blocks.points.is_empty());
    drop(cache);
    let saturated = SharedMemoryBudget::new(0);
    assert_eq!(
        commit_column(&owner, &values, MemoryBudget::DEFAULT, &saturated, None)
            .unwrap()
            .to_affine(),
        expected
    );
    assert_eq!(saturated.peak_bytes(), 0);
    assert_eq!(partial.calls(), 4, "both partials used bounded fallback");
    assert_eq!(
        owner
            .commit_public_column_cancellable(&values, MemoryBudget::new(0), None)
            .unwrap(),
        expected
    );
    assert_eq!(
        partial.calls(),
        4,
        "exact computed partials need no new scratch"
    );
}

fn cancel_active<C: PastaCurve>() {
    use std::{
        sync::atomic::{AtomicBool, Ordering},
        time::{Duration, Instant},
    };
    let owner = PinnedParams::<C>::derive(14).unwrap();
    let values = vec![-C::ScalarExt::ONE; 16_384];
    let shared = SharedMemoryBudget::new(64 << 20);
    let token = CancellationToken::new();
    let done = AtomicBool::new(false);
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(4)
        .build()
        .unwrap();
    let (started, observed) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        let task = scope.spawn(|| {
            let result = pool.install(|| {
                let partial = CommitmentProbe::start_partial();
                started
                    .send(crate::pcs::ipa::commit::test_observation::partial_observation().unwrap())
                    .unwrap();
                let column = crate::pcs::ipa::HashedPublicColumn::with_canonical_sink(
                    &values,
                    |_| {},
                    Some(&token),
                )
                .unwrap();
                let result = owner.commit_hashed_with_shared_budget(
                    &column,
                    MemoryBudget::DEFAULT,
                    &shared,
                    Some(&token),
                );
                (result, partial.calls())
            });
            done.store(true, Ordering::Release);
            result
        });
        let calls = observed.recv_timeout(Duration::from_secs(20)).unwrap();
        let until = Instant::now() + Duration::from_secs(20);
        while (shared.in_use_bytes() == 0 || calls.load(Ordering::Relaxed) < 2)
            && !done.load(Ordering::Acquire)
            && Instant::now() < until
        {
            std::thread::yield_now();
        }
        let active = shared.in_use_bytes() > 0 && calls.load(Ordering::Relaxed) >= 2;
        token.cancel();
        let (result, calls) = task.join().unwrap();
        assert!(
            active && calls >= 2,
            "cancel actually entered parallel partial MSM workers"
        );
        assert_eq!(result, Err(MsmError::Cancelled));
    });
    assert_eq!(shared.in_use_bytes(), 0, "all partial workers joined");
    assert!(shared.peak_bytes() <= shared.limit_bytes());
    assert!(owner.public_columns.lock().unwrap().points.is_empty());
    let expected = reference(&owner, &values);
    assert_eq!(
        owner
            .commit_public_column_cancellable(&values, MemoryBudget::DEFAULT, None)
            .unwrap(),
        expected
    );
}

#[test]
fn active_partial_cancellation_joins_releases_scratch_and_retries_on_both_curves() {
    cancel_active::<Ep>();
    cancel_active::<Eq>();
}

fn ordered_waves<C: PastaCurve>() {
    let owner = PinnedParams::<C>::derive(14).unwrap();
    let values: Vec<_> = (0..BLOCK_ROWS * 9 + 13)
        .map(|row| {
            if row / BLOCK_ROWS == 3 {
                C::ScalarExt::ZERO
            } else {
                C::ScalarExt::from(row as u64 + 1)
            }
        })
        .collect();
    let expected = reference(&owner, &values);
    let partial = CommitmentProbe::start_partial();
    assert_eq!(
        owner
            .commit_public_column_cancellable(&values, MemoryBudget::DEFAULT, None)
            .unwrap(),
        expected
    );
    let expected_order: Vec<_> = values
        .chunks(BLOCK_ROWS)
        .enumerate()
        .filter_map(|(index, block)| block_digest(index * BLOCK_ROWS, block, None).unwrap())
        .collect();
    assert_eq!(partial.calls(), expected_order.len());
    let cache = owner.public_columns.lock().unwrap();
    assert_eq!(
        cache.blocks.order.iter().copied().collect::<Vec<_>>(),
        expected_order,
        "worker completion order never changes FIFO admission"
    );
}

#[test]
fn multiwave_points_and_fifo_order_include_zero_blocks_and_short_tail_on_both_curves() {
    ordered_waves::<Ep>();
    ordered_waves::<Eq>();
}
