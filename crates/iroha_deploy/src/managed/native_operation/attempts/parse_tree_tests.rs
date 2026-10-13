//! Genuine freshly parsed rows retain canonical charges, lazy refusal order and source custody.

use super::*;
use crate::managed::Error;

fn canonical_rows(fixture: &Fixture) {
    let mut previous = fixture.reserve();
    fixture.commit(&previous);
    for ordinal in 1..=2_u8 {
        let next = fixture
            .history()
            .unwrap()
            .reserve(
                &fixture.operation,
                Origin::Generated {
                    ordinal,
                    epoch: [ordinal; 32],
                    parent_intent: [0x73; 32],
                },
                fixture.terms.clone(),
            )
            .unwrap();
        let receipt = fixture
            .wallet
            .retire_initial_reserve_policy_unprepared(
                &previous.wallet_path(),
                &fixture.request(&previous),
            )
            .unwrap();
        retire_request(&previous, &next, &receipt).unwrap();
        let retained = fixture.retain(&next);
        commit(&next, Some(&previous), Observation::ordinary(), &retained).unwrap();
        previous = next;
    }
}

fn observed(
    fixture: &Fixture,
    retained: Option<&History>,
) -> (Result<History>, parse_digest_tests::Counts) {
    let counter = parse_digest_tests::Counter::begin();
    let result = match retained {
        Some(prior) => History::read_retained(
            &fixture.operation,
            Purpose::ReservePolicy,
            fixture.semantic,
            &HistoryScope::FixedBody,
            prior,
        ),
        None => fixture.history(),
    };
    (result, counter.finish())
}

fn require_three_rows(counts: parse_digest_tests::Counts) {
    assert_eq!(counts.reads, 2);
    assert_eq!(counts.decoded, 12);
    assert_eq!(counts.requested, 10);
    assert_eq!(counts.computed, 3);
    assert_eq!(&counts.by_ordinal[..3], &[1, 1, 1]);
    assert!(counts.by_ordinal[3..].iter().all(|count| *count == 0));
}

#[test]
fn fresh_parse_tree_keeps_shared_and_reopened_rows_lazy_refusals_and_exact_source_retry() {
    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let mut peers = UnavailablePeers::start(&fixture.prepared);
    canonical_rows(&fixture);
    let (fresh, counts) = observed(&fixture, None);
    require_three_rows(counts);
    let fresh = fresh.unwrap();
    let (shared, counts) = observed(&fixture, Some(&fresh));
    require_three_rows(counts);
    let shared = shared.unwrap();
    assert!(shared.dispatch == fresh.dispatch);
    assert_eq!(shared.selected().unwrap().unwrap().ordinal(), 3);
    let root = shared.root.as_ref().unwrap();
    let root_names = root.entries(MAX_ATTEMPTS).unwrap();
    let first = &shared.attempts[0];
    let authorization = metadata::test_read_component(
        &fixture.operation,
        Some(first.ordinal()),
        "authorization.nrt",
    )
    .unwrap()
    .unwrap();
    let observation =
        metadata::test_read_component(&fixture.operation, Some(first.ordinal()), "observation.nrt")
            .unwrap()
            .unwrap();
    let wallet = std::fs::read(shared.attempts[2].wallet_path().join("preparation.json")).unwrap();
    let mut reopened = fixture.history().unwrap();
    {
        // This fresh parser result owns its records; retained immutable predecessors stay sealed.
        let HistoryRecordsOwner::Owned(records) = &mut reopened.records else {
            panic!("the fresh parser must own its records");
        };
        records.root = Some(PrivateDirectory::open(records.root.as_ref().unwrap().path()).unwrap());
        for attempt in &mut records.attempts {
            attempt.directory = PrivateDirectory::open(attempt.directory.path()).unwrap();
        }
    }
    // Independently reopened owners share no native Arc prefix with the selected root.
    let (fallback, counts) = observed(&fixture, Some(&reopened));
    require_three_rows(counts);
    let fallback = fallback.unwrap();
    assert!(fallback.dispatch == shared.dispatch);
    assert_eq!(fallback.selected().unwrap().unwrap().ordinal(), 3);

    first
        .directory
        .write_atomic("foreign.nrt", b"foreign", PublishMode::CreateNew)
        .unwrap();
    let (refused, counts) = observed(&fixture, None);
    assert!(
        matches!(&refused, Err(Error::Invalid(message)) if message == "dispatch attempt contains unknown material"),
        "{:?}",
        refused.as_ref().err()
    );
    assert_eq!(counts.reads, 1);
    assert_eq!(counts.decoded, 1);
    std::fs::remove_file(first.directory.path().join("foreign.nrt")).unwrap();
    let mut changed = first.authorization.clone();
    changed.semantic = [0x93; 32];
    metadata::test_replace_component(
        &fixture.operation,
        Some(first.ordinal()),
        "authorization.nrt",
        Some(&encode(&changed, MAX_RECORD_BYTES).unwrap()),
    )
    .unwrap();
    metadata::test_replace_component(
        &fixture.operation,
        Some(first.ordinal()),
        "observation.nrt",
        Some(b"not canonical"),
    )
    .unwrap();
    let (refused, counts) = observed(&fixture, None);
    assert!(
        matches!(&refused, Err(Error::Invalid(message)) if message == "dispatch authorization changed its original purpose, intent or predecessor"),
        "{:?}",
        refused.as_ref().err()
    );
    assert_eq!(counts.reads, 1);
    assert_eq!(counts.decoded, 2);
    assert_eq!(counts.computed, 0);
    metadata::test_replace_component(
        &fixture.operation,
        Some(first.ordinal()),
        "authorization.nrt",
        Some(&authorization),
    )
    .unwrap();
    let (refused, counts) = observed(&fixture, None);
    assert!(
        matches!(&refused, Err(Error::Invalid(message)) if message == "invalid canonical dispatch custody record"),
        "{:?}",
        refused.as_ref().err()
    );
    assert_eq!(counts.reads, 1);
    assert_eq!(counts.decoded, 2);
    metadata::test_replace_component(
        &fixture.operation,
        Some(first.ordinal()),
        "observation.nrt",
        Some(&observation),
    )
    .unwrap();
    metadata::test_replace_component(
        &fixture.operation,
        Some(first.ordinal()),
        "authorization.nrt",
        None,
    )
    .unwrap();
    let (refused, counts) = observed(&fixture, None);
    assert!(
        matches!(&refused, Err(Error::Invalid(message)) if message == "dispatch material exists without its authorization"),
        "{:?}",
        refused.as_ref().err()
    );
    assert_eq!(counts.reads, 1);
    assert_eq!(counts.decoded, 1);
    metadata::test_replace_component(
        &fixture.operation,
        Some(first.ordinal()),
        "authorization.nrt",
        Some(&authorization),
    )
    .unwrap();
    let extra = root.create_child("0042").unwrap();
    let (refused, counts) = observed(&fixture, None);
    assert!(
        matches!(&refused, Err(Error::Invalid(message)) if message == "dispatch attempt inventory has a gap or foreign name"),
        "{:?}",
        refused.as_ref().err()
    );
    assert_eq!(counts.reads, 1);
    drop(extra);
    std::fs::remove_dir(root.path().join("0042")).unwrap();
    let original_middle = root.path().join("0002");
    let held_middle = fixture._temporary.path().join("held-middle");
    std::fs::rename(&original_middle, &held_middle).unwrap();
    let (refused, counts) = observed(&fixture, None);
    assert!(
        matches!(&refused, Err(Error::Invalid(message)) if message == "dispatch attempt inventory has a gap or foreign name"),
        "{:?}",
        refused.as_ref().err()
    );
    assert_eq!(counts.reads, 1);
    std::fs::rename(&held_middle, &original_middle).unwrap();
    let (retried, counts) = observed(&fixture, Some(&shared));
    require_three_rows(counts);
    retried
        .unwrap()
        .verify_wallets(|attempt| fixture.inspect(attempt))
        .unwrap();
    assert_eq!(root.entries(MAX_ATTEMPTS).unwrap(), root_names);
    assert_eq!(
        metadata::test_read_component(
            &fixture.operation,
            Some(first.ordinal()),
            "authorization.nrt"
        )
        .unwrap()
        .unwrap(),
        authorization
    );
    assert_eq!(
        std::fs::read(shared.attempts[2].wallet_path().join("preparation.json")).unwrap(),
        wallet
    );
    assert!(
        !shared.attempts[2]
            .wallet_path()
            .join("payload.json")
            .exists()
    );
    assert!(
        !shared.attempts[2]
            .wallet_path()
            .join("operation.json")
            .exists()
    );
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

#[test]
fn fresh_parse_tree_keeps_late_active_allocation_refusal_and_exact_cap_retry() {
    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let attempt = fixture.reserve();
    let authorization = metadata::test_read_component(
        &fixture.operation,
        Some(attempt.ordinal()),
        "authorization.nrt",
    )
    .unwrap()
    .unwrap();
    let wide = norito::DecodeLimits::new(
        MAX_RECORD_BYTES,
        MAX_RECORD_BYTES,
        MAX_RECORD_BYTES,
        64 * 1024 * 1024,
        32,
    );
    let dispatch_budget = norito::core::DecodeBudgetContext::new(wide);
    dispatch_budget
        .with(|| {
            fixture.operation.read_scope(|reader| {
                metadata::load_in_scope(reader).and_then(|image| image.read::<Dispatch>(None, 0))
            })
        })
        .unwrap();
    let dispatch_charge = usize::try_from(dispatch_budget.consumed_allocated_bytes()).unwrap();
    assert!(dispatch_charge > 0);
    for remaining in [0, 1] {
        let counter = parse_digest_tests::Counter::begin();
        let limits = norito::DecodeLimits::new(
            MAX_RECORD_BYTES,
            MAX_RECORD_BYTES,
            MAX_RECORD_BYTES,
            dispatch_charge + remaining,
            32,
        );
        let refused = norito::core::with_decode_limits_scope(limits, || fixture.history());
        let counts = counter.finish();
        assert!(
            matches!(&refused, Err(Error::Invalid(message)) if message == "invalid canonical dispatch custody record"),
            "{:?}",
            refused.as_ref().err()
        );
        assert_eq!(counts.reads, 1);
        assert_eq!(counts.decoded, 1);
        assert_eq!(counts.computed, 0);
    }
    let full_budget = norito::core::DecodeBudgetContext::new(wide);
    let (accepted, counts) = full_budget.with(|| observed(&fixture, None));
    assert_eq!(accepted.unwrap().reserved_attempt_count(), 1);
    assert_eq!(counts.reads, 2);
    assert_eq!(counts.decoded, 2);
    let exact_charge = usize::try_from(full_budget.consumed_allocated_bytes()).unwrap();
    assert!(exact_charge > dispatch_charge + 1);
    let exact = norito::DecodeLimits::new(
        MAX_RECORD_BYTES,
        MAX_RECORD_BYTES,
        MAX_RECORD_BYTES,
        exact_charge,
        32,
    );
    let (retried, exact_counts) =
        norito::core::with_decode_limits_scope(exact, || observed(&fixture, None));
    assert_eq!(retried.unwrap().reserved_attempt_count(), 1);
    assert_eq!(exact_counts, counts);
    assert_eq!(
        metadata::test_read_component(
            &fixture.operation,
            Some(attempt.ordinal()),
            "authorization.nrt"
        )
        .unwrap()
        .unwrap(),
        authorization
    );
    assert!(!attempt.wallet_path().exists());
}

#[cfg(unix)]
#[test]
fn fresh_parse_tree_anchor_exit_closes_real_row_results_and_restores_original_sources() {
    use std::{fs, os::unix::fs::PermissionsExt as _};
    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    fixture.reserve();
    let history = fixture.history().unwrap();
    let root = history.root.as_ref().unwrap();
    let attempt = &history.attempts[0];
    let original = metadata::test_read_component(
        &fixture.operation,
        Some(attempt.ordinal()),
        "authorization.nrt",
    )
    .unwrap()
    .unwrap();
    for kind in ["present", "absence", "decoder_error", "native_not_found"] {
        if kind == "decoder_error" {
            metadata::test_replace_component(
                &fixture.operation,
                Some(attempt.ordinal()),
                "authorization.nrt",
                Some(b"not canonical"),
            )
            .unwrap();
        }
        let refused: Result<Option<Authorization>> = root.read_tree_scope(|tree| {
            let result: Result<Option<Authorization>> = tree.read_scope(&attempt.directory, |reader| {
                    if kind == "native_not_found" {
                        return reader.read("missing.nrt", MAX_RECORD_BYTES, decode_record::<Authorization>)
                            .map_err(Error::from).and_then(|value| value.map(Some));
                    }
                    metadata::load(&fixture.operation).and_then(|image| image.read::<Authorization>(Some(attempt.ordinal()), usize::from(kind == "absence")))
                });
            match kind {
                "present" => assert!(result.as_ref().unwrap().as_ref() == Some(&attempt.authorization)),
                "absence" => assert!(result.as_ref().unwrap().is_none()),
                "decoder_error" => assert!(matches!(&result, Err(Error::Invalid(message)) if message == "invalid canonical dispatch custody record")),
                _ => assert!(matches!(&result, Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound)),
            }
            fs::set_permissions(fixture.operation.path(), fs::Permissions::from_mode(0o755)).unwrap();
            result
        });
        assert!(
            matches!(&refused, Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied),
            "{:?}",
            refused.as_ref().err()
        );
        fs::set_permissions(fixture.operation.path(), fs::Permissions::from_mode(0o700)).unwrap();
        if kind == "decoder_error" {
            metadata::test_replace_component(
                &fixture.operation,
                Some(attempt.ordinal()),
                "authorization.nrt",
                Some(&original),
            )
            .unwrap();
        }
        assert_eq!(fixture.history().unwrap().reserved_attempt_count(), 1);
    }
    let suffix_refused: Result<Option<Authorization>> = root.read_tree_scope(|tree| {
        tree.read_scope(&attempt.directory, |_reader| {
            let result = metadata::load(&fixture.operation)
                .and_then(|image| image.read::<Authorization>(Some(attempt.ordinal()), 0));
            assert!(result.as_ref().unwrap().as_ref() == Some(&attempt.authorization));
            fs::set_permissions(attempt.directory.path(), fs::Permissions::from_mode(0o755))
                .unwrap();
            result
        })
    });
    assert!(
        matches!(&suffix_refused, Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied)
    );
    fs::set_permissions(attempt.directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let restored: Option<Authorization> = root
        .read_tree_scope(|tree| {
            let result = tree.read_scope(&attempt.directory, |_reader| {
                metadata::load(&fixture.operation)
                    .and_then(|image| image.read::<Authorization>(Some(attempt.ordinal()), 0))
            })?;
            fs::set_permissions(fixture.operation.path(), fs::Permissions::from_mode(0o755))
                .unwrap();
            fs::set_permissions(fixture.operation.path(), fs::Permissions::from_mode(0o700))
                .unwrap();
            Ok::<_, Error>(result)
        })
        .unwrap();
    // Entry/exit consolidation intentionally cannot observe a fully restored interior change.
    assert!(restored.as_ref() == Some(&attempt.authorization));
    assert_eq!(
        metadata::test_read_component(
            &fixture.operation,
            Some(attempt.ordinal()),
            "authorization.nrt"
        )
        .unwrap()
        .unwrap(),
        original
    );
    history.require_current_local(None).unwrap();
    assert!(!attempt.wallet_path().exists());
}
