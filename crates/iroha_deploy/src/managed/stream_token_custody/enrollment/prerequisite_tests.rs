//! Genuine original prerequisites share one parse and retain canonical custody refusal.

use super::*;
use crate::managed::{
    native_operation::test_support::UnavailablePeers,
    stream_token_custody::{
        renewal_tests::{Fixture, wait_until},
        tests::count_wallet_constructions,
    },
};
use std::{cell::Cell, path::PathBuf};

thread_local! {
    static CONFIGURATION_READS: Cell<Option<usize>> = const { Cell::new(None) };
}

pub(super) fn record_configuration_read() {
    CONFIGURATION_READS.with(|value| {
        if let Some(count) = value.get() {
            value.set(Some(
                count.checked_add(1).expect("configuration read count"),
            ));
        }
    });
}

fn counted<T>(action: impl FnOnce() -> T) -> (T, usize, usize) {
    struct Restore(Option<usize>);
    impl Drop for Restore {
        fn drop(&mut self) {
            CONFIGURATION_READS.with(|value| value.set(self.0));
        }
    }
    let _restore = Restore(CONFIGURATION_READS.with(|value| value.replace(Some(0))));
    let (result, wallets) = count_wallet_constructions(action);
    let configurations = CONFIGURATION_READS.with(|value| value.get().unwrap());
    (result, configurations, wallets)
}

fn assert_same(actual: &RetainedCustodyEnrollment, expected: &RetainedCustodyEnrollment) {
    assert_eq!(actual.bytes(), expected.bytes());
    assert_eq!(actual.record_digest(), expected.record_digest());
    assert_eq!(actual.finalized(), expected.finalized());
}

#[test]
fn renewal_contexts_verify_configuration_and_read_initial_history_once() {
    let _guard = crate::managed::native_test_guard();
    let fixture = Fixture::enrolled(4_000);
    let mut peers = UnavailablePeers::start(&fixture.prepared);
    let deadline = fixture.options.deadline;
    let expected = fixture
        .owner
        .retained_initial_enrollment(&fixture.policy, fixture.initial, deadline)
        .unwrap();
    let (prerequisite, configurations, wallets) =
        counted(|| fixture.owner.retained_initial_prerequisite(deadline));
    let prerequisite = prerequisite.unwrap();
    assert_eq!(configurations, 1);
    // The genuine initial History has an observed wallet. Its canonical inspector constructs
    // exactly one owner per read; zero would omit inspection and two would repeat the parse.
    assert_eq!(wallets, 1);
    assert_eq!(prerequisite.policy, fixture.policy);
    assert_same(&prerequisite.enrollment, &expected);

    wait_until(
        fixture.initial.issued_at_unix_ms + 2_000,
        Duration::from_secs(4),
    );
    let (checkpoint, current) = fixture.current();
    let utc = now_ms().unwrap() + 60_000;
    let terms = Terms::new(utc, &fixture.options).unwrap();
    let (unsigned, configurations, wallets) = counted(|| {
        fixture.owner.select_renewal_unsigned(
            2,
            &fixture.policy,
            &current,
            &checkpoint,
            &terms,
            deadline,
        )
    });
    let unsigned = unsigned.unwrap();
    assert_eq!((configurations, wallets), (1, 1));
    let history = fixture.owner.bootstrap_native_body(
        &fixture.native,
        &current,
        CustodyPurpose::Renewal(2),
        unsigned,
        utc,
        &fixture.options,
    );
    let original = history
        .original()
        .unwrap()
        .expect("actual signed renewal body");
    let (validated, configurations, wallets) =
        counted(|| fixture.owner.validate_renewal_context(original, deadline));
    validated.unwrap();
    assert_eq!((configurations, wallets), (1, 1));

    let configured = journal::required_original(
        &fixture
            .owner
            .authority
            .directory
            .open_child("configure")
            .unwrap(),
    )
    .unwrap();
    let mut earlier = original.clone();
    earlier.checkpoint = configured.checkpoint.clone();
    assert!(
        fixture
            .owner
            .validate_renewal_context(&earlier, deadline)
            .is_err()
    );
    let mut wrong_policy = fixture.policy.clone();
    wrong_policy.max_anchor_age_ms -= 1;
    assert!(
        fixture
            .owner
            .retained_initial_enrollment(&wrong_policy, fixture.initial, deadline)
            .is_err()
    );
    let mut wrong_interval = fixture.initial;
    wrong_interval.expires_at_unix_ms += 1;
    assert!(
        fixture
            .owner
            .retained_initial_enrollment(&fixture.policy, wrong_interval, deadline)
            .is_err()
    );
    assert!(peers.requests.lock().unwrap().is_empty());
    assert_eq!(fixture.native.chain.height(), 4);
    peers.finish();
}

fn retained_paths(fixture: &Fixture) -> Vec<(PathBuf, &'static str, usize)> {
    let configured_root = fixture
        .owner
        .authority
        .directory
        .open_child("configure")
        .unwrap();
    let configured = journal::required_original(&configured_root).unwrap();
    let initial = BodyHistory::open(&fixture.owner, CustodyPurpose::InitialEnroll)
        .unwrap()
        .unwrap();
    let initial_body = initial.dispatch().unwrap().0.path().to_owned();
    let initial = initial.into_selected().unwrap();
    let mut paths = Vec::new();
    for (body, attempt) in [
        (
            configured_root.path().to_owned(),
            configured.directory().path().to_owned(),
        ),
        (initial_body, initial.directory().path().to_owned()),
    ] {
        paths.push((body, "original.nrt", journal::MAX_ORIGINAL_BYTES));
        paths.push((attempt.clone(), "carrier.nrt", MAX_CHECKPOINT_BYTES));
        for name in ["preparation.json", "operation.json"] {
            paths.push((attempt.join("transaction"), name, 4 * 1024 * 1024));
        }
    }
    paths
}

#[test]
fn initial_prerequisite_refuses_changed_configure_and_initial_original_wallet_and_carrier() {
    let _guard = crate::managed::native_test_guard();
    let fixture = Fixture::enrolled(4_000);
    let mut peers = UnavailablePeers::start(&fixture.prepared);
    let deadline = fixture.options.deadline;
    let expected = fixture
        .owner
        .retained_initial_prerequisite(deadline)
        .unwrap();
    for (path, name, maximum) in retained_paths(&fixture) {
        let directory = PrivateDirectory::open_exact(&path).unwrap();
        let original = directory.read(name, maximum).unwrap();
        directory
            .write_atomic(name, &[0xff], PublishMode::Replace)
            .unwrap();
        assert!(
            fixture
                .owner
                .retained_initial_prerequisite(deadline)
                .is_err(),
            "changed {path:?}/{name}"
        );
        directory
            .write_atomic(name, &original, PublishMode::Replace)
            .unwrap();
        let restored = fixture
            .owner
            .retained_initial_prerequisite(deadline)
            .unwrap();
        assert_eq!(restored.policy, expected.policy);
        assert_same(&restored.enrollment, &expected.enrollment);
    }
    assert!(peers.requests.lock().unwrap().is_empty());
    assert_eq!(fixture.native.chain.height(), 4);
    peers.finish();
}

#[test]
fn selected_initial_handoff_rechecks_current_original_wallet_and_carrier() {
    let _guard = crate::managed::native_test_guard();
    let fixture = Fixture::enrolled(4_000);
    let mut peers = UnavailablePeers::start(&fixture.prepared);
    let deadline = fixture.options.deadline;
    let expected = fixture
        .owner
        .retained_initial_prerequisite(deadline)
        .unwrap();
    // Select from the genuine graph first, then mutate only one source before the sole verifier.
    for (path, name, maximum) in retained_paths(&fixture).into_iter().skip(4) {
        let (policy, configured) = fixture.owner.retained_configuration(deadline).unwrap();
        let (selected, interval) = fixture
            .owner
            .inspect_initial_selection(&policy)
            .unwrap()
            .unwrap();
        let directory = PrivateDirectory::open_exact(&path).unwrap();
        let original = directory.read(name, maximum).unwrap();
        directory
            .write_atomic(name, &[0xff], PublishMode::Replace)
            .unwrap();
        assert!(
            fixture
                .owner
                .verify_retained_enrollment(
                    CustodyPurpose::InitialEnroll,
                    &policy,
                    Some(interval),
                    &configured,
                    selected,
                    deadline,
                )
                .is_err(),
            "source changed after selection: {path:?}/{name}"
        );
        directory
            .write_atomic(name, &original, PublishMode::Replace)
            .unwrap();
        let restored = fixture
            .owner
            .retained_initial_prerequisite(deadline)
            .unwrap();
        assert_same(&restored.enrollment, &expected.enrollment);
    }
    assert!(peers.requests.lock().unwrap().is_empty());
    assert_eq!(fixture.native.chain.height(), 4);
    peers.finish();
}

#[test]
fn generated_authorization_verifies_configure_once_and_rechecks_each_call() {
    use crate::managed::native_operation::authorization::DispatchAuthorization;

    let _guard = crate::managed::native_test_guard();
    let fixture = Fixture::enrolled(4_000);
    let mut peers = UnavailablePeers::start(&fixture.prepared);
    let deadline = fixture.options.deadline;
    wait_until(
        fixture.initial.issued_at_unix_ms + 2_000,
        Duration::from_secs(4),
    );
    let mut turn = fixture.renewal_turn();
    let (checkpoint, current) = fixture.current();
    let terms = Terms::new(now_ms().unwrap() + 60_000, &fixture.options).unwrap();
    let unsigned = fixture
        .owner
        .select_renewal_unsigned(2, &fixture.policy, &current, &checkpoint, &terms, deadline)
        .unwrap();
    let history = BodyHistory::initialize(
        &fixture.owner,
        CustodyPurpose::Renewal(2),
        unsigned,
        &Fees::from_options(&fixture.options).unwrap(),
        &SigningTurn::RenewalSelection(&turn),
        deadline,
    )
    .unwrap();
    let (authorized, configurations, _) =
        counted(|| turn.authorize_retained(&fixture.owner, &history, deadline));
    let original_origin = authorized.unwrap().origin().unwrap();
    assert_eq!(configurations, 1);
    let (authorized, configurations, _) =
        counted(|| turn.authorize_retained(&fixture.owner, &history, deadline));
    assert!(authorized.unwrap().origin().unwrap() == original_origin);
    assert_eq!(configurations, 1);

    // A new call must authenticate current retained Configure inputs, even after an epoch exists.
    let (path, name, maximum) = retained_paths(&fixture).remove(1);
    let directory = PrivateDirectory::open_exact(&path).unwrap();
    let original = directory.read(name, maximum).unwrap();
    directory
        .write_atomic(name, &[0xff], PublishMode::Replace)
        .unwrap();
    assert!(
        turn.authorize_retained(&fixture.owner, &history, deadline)
            .is_err()
    );
    directory
        .write_atomic(name, &original, PublishMode::Replace)
        .unwrap();
    let (authorized, configurations, _) =
        counted(|| turn.authorize_retained(&fixture.owner, &history, deadline));
    assert!(authorized.unwrap().origin().unwrap() == original_origin);
    assert_eq!(configurations, 1);
    assert!(history.original().unwrap().is_none());
    assert_eq!(fixture.native.chain.height(), 4);
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

#[test]
fn configure_handoff_rechecks_exact_original_wallet_carrier_and_deadline() {
    let _guard = crate::managed::native_test_guard();
    let fixture = Fixture::enrolled(4_000);
    let mut peers = UnavailablePeers::start(&fixture.prepared);
    let deadline = fixture.options.deadline;
    let expected = fixture
        .owner
        .retained_initial_prerequisite(deadline)
        .unwrap();
    for (path, name, maximum) in retained_paths(&fixture).into_iter().take(4) {
        let (restored, configurations, _) = counted(|| {
            fixture
                .owner
                .read_configuration(deadline)?
                .into_initial_prerequisite(deadline)
        });
        let restored = restored.unwrap();
        assert_eq!(configurations, 1);
        assert_eq!(restored.policy, expected.policy);
        assert_same(&restored.enrollment, &expected.enrollment);

        let retained = fixture.owner.read_configuration(deadline).unwrap();
        let directory = PrivateDirectory::open_exact(&path).unwrap();
        let original = directory.read(name, maximum).unwrap();
        directory
            .write_atomic(name, &[0xff], PublishMode::Replace)
            .unwrap();
        assert!(
            retained.into_initial_prerequisite(deadline).is_err(),
            "source changed during Configure handoff: {path:?}/{name}"
        );
        directory
            .write_atomic(name, &original, PublishMode::Replace)
            .unwrap();
        let restored = fixture
            .owner
            .read_configuration(deadline)
            .unwrap()
            .into_initial_prerequisite(deadline)
            .unwrap();
        assert_same(&restored.enrollment, &expected.enrollment);
    }
    let (path, name, maximum) = retained_paths(&fixture).remove(1);
    let directory = PrivateDirectory::open_exact(&path).unwrap();
    let original = directory.read(name, maximum).unwrap();
    let retained = fixture.owner.read_configuration(deadline).unwrap();
    std::fs::remove_file(directory.path().join(name)).unwrap();
    assert!(retained.into_initial_prerequisite(deadline).is_err());
    directory
        .write_atomic(name, &original, PublishMode::CreateNew)
        .unwrap();
    let restored = fixture
        .owner
        .read_configuration(deadline)
        .unwrap()
        .into_initial_prerequisite(deadline)
        .unwrap();
    assert_same(&restored.enrollment, &expected.enrollment);
    let retained = fixture.owner.read_configuration(deadline).unwrap();
    assert!(retained.into_initial_prerequisite(Instant::now()).is_err());
    let restored = fixture
        .owner
        .retained_initial_prerequisite(deadline)
        .unwrap();
    assert_same(&restored.enrollment, &expected.enrollment);
    assert_eq!(fixture.native.chain.height(), 4);
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

#[test]
fn renewal_selection_reuses_exact_authenticated_checkpoint_and_rejects_substitution() {
    let _guard = crate::managed::native_test_guard();
    let mut fixture = Fixture::enrolled(4_000);
    let mut peers = UnavailablePeers::start(&fixture.prepared);
    let deadline = fixture.options.deadline;
    wait_until(
        fixture.initial.issued_at_unix_ms + 2_000,
        Duration::from_secs(4),
    );
    let (checkpoint, current) = fixture.current();
    let before = checkpoint_bytes(&checkpoint).unwrap();
    let terms = Terms::new(now_ms().unwrap() + 60_000, &fixture.options).unwrap();
    let unsigned = fixture
        .owner
        .select_renewal_unsigned(2, &fixture.policy, &current, &checkpoint, &terms, deadline)
        .unwrap();
    assert_eq!(unsigned.checkpoint, before);
    let validate = |value: &body_history::UnsignedEnrollment, verifier: &FinalityVerifier| {
        value.validate_with_checkpoint(&fixture.owner, CustodyPurpose::Renewal(2), verifier, || {
            fixture.owner.authority.provider_plan()
        })
    };
    validate(&unsigned, &checkpoint).unwrap();
    unsigned
        .validate(&fixture.owner, CustodyPurpose::Renewal(2), || {
            fixture.owner.authority.provider_plan()
        })
        .unwrap();
    fixture
        .owner
        .validate_unsigned_renewal_context_at(&unsigned, &checkpoint, deadline)
        .unwrap();
    fixture
        .owner
        .validate_unsigned_renewal_context_using(&unsigned, deadline, || {
            fixture.owner.retained_initial_prerequisite(deadline)
        })
        .unwrap();

    let mut changed = unsigned.clone();
    changed.checkpoint.push(0);
    assert!(matches!(
        validate(&changed, &checkpoint),
        Err(crate::managed::Error::Invalid(message))
            if message == "unsigned enrollment differs from retained checkpoint"
    ));
    assert!(
        changed
            .validate(&fixture.owner, CustodyPurpose::Renewal(2), || {
                fixture.owner.authority.provider_plan()
            })
            .is_err()
    );
    assert!(matches!(
        fixture.owner.validate_unsigned_renewal_context_at(&changed, &checkpoint, deadline),
        Err(crate::managed::Error::Invalid(message))
            if message == "unsigned enrollment differs from retained checkpoint"
    ));

    let initial = fixture
        .owner
        .required_enrollment(CustodyPurpose::InitialEnroll)
        .unwrap();
    let earlier = fixture
        .owner
        .authority
        .decode_checkpoint(&initial.checkpoint)
        .unwrap();
    drop(initial);
    assert_eq!(earlier.checkpoint().height(), 3);
    assert_eq!(checkpoint.checkpoint().height(), 4);
    assert!(matches!(
        validate(&unsigned, &earlier),
        Err(crate::managed::Error::Invalid(message))
            if message == "unsigned enrollment differs from retained checkpoint"
    ));
    assert!(matches!(
        fixture.owner.validate_unsigned_renewal_context_at(&unsigned, &earlier, deadline),
        Err(crate::managed::Error::Invalid(message))
            if message == "unsigned enrollment differs from retained checkpoint"
    ));
    let mut changed = unsigned.clone();
    changed.statement.anchor.height += 1;
    assert!(validate(&changed, &checkpoint).is_err());
    assert!(
        changed
            .validate(&fixture.owner, CustodyPurpose::Renewal(2), || {
                fixture.owner.authority.provider_plan()
            })
            .is_err()
    );
    assert!(
        unsigned
            .validate_with_checkpoint(
                &fixture.owner,
                CustodyPurpose::Renewal(3),
                &checkpoint,
                || fixture.owner.authority.provider_plan(),
            )
            .is_err()
    );

    // Reusing the caller's immutable checkpoint never reuses the retained prerequisites.
    let (path, name, maximum) = retained_paths(&fixture).remove(1);
    let directory = PrivateDirectory::open_exact(&path).unwrap();
    let original = directory.read(name, maximum).unwrap();
    directory
        .write_atomic(name, &[0xff], PublishMode::Replace)
        .unwrap();
    assert!(
        fixture
            .owner
            .validate_unsigned_renewal_context_at(&unsigned, &checkpoint, deadline)
            .is_err()
    );
    directory
        .write_atomic(name, &original, PublishMode::Replace)
        .unwrap();
    fixture
        .owner
        .validate_unsigned_renewal_context_at(&unsigned, &checkpoint, deadline)
        .unwrap();
    assert!(
        fixture
            .owner
            .validate_unsigned_renewal_context_at(&unsigned, &checkpoint, Instant::now())
            .is_err()
    );
    validate(&unsigned, &checkpoint).unwrap();

    // Neither original authority field may be substituted while these exact proof bytes stay
    // unchanged. Check the matcher directly so unrelated profile fences cannot mask rejection.
    let network = fixture.owner.authority.config.network_id;
    fixture.owner.authority.config.network_id = iroha_data_model::NetworkId::from_genesis_hash(
        iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(b"foreign renewal handoff network")),
    );
    assert_ne!(fixture.owner.authority.config.network_id, network);
    assert_eq!(unsigned.checkpoint, before);
    assert_eq!(checkpoint_bytes(&checkpoint).unwrap(), before);
    assert!(matches!(
        unsigned.matching_checkpoint(&fixture.owner, &checkpoint),
        Err(crate::managed::Error::Invalid(message))
            if message == "unsigned enrollment differs from retained checkpoint"
    ));
    fixture.owner.authority.config.network_id = network;
    unsigned
        .matching_checkpoint(&fixture.owner, &checkpoint)
        .unwrap();
    let chain = fixture.owner.authority.config.chain.clone();
    fixture.owner.authority.config.chain = "different-renewal-handoff-chain".parse().unwrap();
    assert_ne!(fixture.owner.authority.config.chain, chain);
    assert_eq!(unsigned.checkpoint, before);
    assert_eq!(checkpoint_bytes(&checkpoint).unwrap(), before);
    assert!(matches!(
        unsigned.matching_checkpoint(&fixture.owner, &checkpoint),
        Err(crate::managed::Error::Invalid(message))
            if message == "unsigned enrollment differs from retained checkpoint"
    ));
    fixture.owner.authority.config.chain = chain;
    unsigned
        .matching_checkpoint(&fixture.owner, &checkpoint)
        .unwrap();
    unsigned
        .validate_with_checkpoint(
            &fixture.owner,
            CustodyPurpose::Renewal(2),
            &checkpoint,
            || fixture.owner.authority.provider_plan(),
        )
        .unwrap();
    assert_eq!(checkpoint_bytes(&checkpoint).unwrap(), before);
    assert_eq!(fixture.native.chain.height(), 4);
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

#[test]
fn retained_carriers_share_exact_checkpoint_imports_and_recheck_transaction_and_file_custody() {
    let _guard = crate::managed::native_test_guard();
    let fixture = Fixture::enrolled(4_000);
    let mut peers = UnavailablePeers::start(&fixture.prepared);
    let deadline = fixture.options.deadline;
    let expected = fixture
        .owner
        .retained_initial_prerequisite(deadline)
        .unwrap();
    let original = fixture
        .owner
        .required_enrollment(CustodyPurpose::InitialEnroll)
        .unwrap();
    let initial_checkpoint = original.checkpoint.clone();
    let transaction = fixture
        .owner
        .verify_wallet(original.directory(), &original, deadline)
        .unwrap();
    let carrier = read_optional(original.directory(), "carrier.nrt", MAX_CHECKPOINT_BYTES)
        .unwrap()
        .unwrap();
    let directory = PrivateDirectory::open_exact(original.directory().path()).unwrap();
    drop(original);
    let authority = &fixture.owner.authority;
    authority.decode_checkpoint(&carrier).unwrap();
    let imports = authority.test_checkpoint_import_attempts();

    // Configure needs H2 and its H3 carrier. The initial body then consumes that exact H3
    // checkpoint; its successful carrier supplies H4 for the following renewal selection.
    let configured = fixture.owner.read_configuration(deadline).unwrap();
    assert_eq!(configured.carrier, initial_checkpoint);
    assert_eq!(authority.test_checkpoint_import_attempts(), imports);
    // The three distinct genuine paid originals are already warm in the fixed FIFO.
    // Their exact heights and canonical bytes must reuse those imports independently.
    for (bytes, height) in [
        (configured.original.checkpoint.as_slice(), 2),
        (initial_checkpoint.as_slice(), 3),
        (carrier.as_slice(), 4),
    ] {
        let checkpoint = authority.decode_checkpoint(bytes).unwrap();
        assert_eq!(checkpoint.checkpoint().height(), height);
        assert_eq!(checkpoint_bytes(&checkpoint).unwrap().as_slice(), bytes);
    }
    assert_eq!(authority.test_checkpoint_import_attempts(), imports);
    let configure_carrier = configured.carrier.clone();
    let prerequisite = configured.into_initial_prerequisite(deadline).unwrap();
    assert_eq!(prerequisite.policy, expected.policy);
    assert_same(&prerequisite.enrollment, &expected.enrollment);
    assert_eq!(authority.test_checkpoint_import_attempts(), imports);
    assert_eq!(
        checkpoint_bytes(&authority.decode_checkpoint(&carrier).unwrap()).unwrap(),
        carrier
    );
    assert_eq!(authority.test_checkpoint_import_attempts(), imports);

    let retained = authority
        .retained_finality(&directory, &transaction)
        .unwrap()
        .unwrap();
    assert_eq!(&retained, expected.enrollment.finalized());
    assert_eq!(authority.test_checkpoint_import_attempts(), imports);
    let standalone = crate::managed::native_operation::retained_carrier(
        &directory,
        authority.config.network_id,
        authority.config.chain.as_str(),
        &transaction,
    )
    .unwrap()
    .unwrap();
    assert_eq!(standalone, retained);
    assert_eq!(authority.test_checkpoint_import_attempts(), imports);

    // A valid warm checkpoint is not inclusion for a different original transaction.
    directory
        .write_atomic("carrier.nrt", &configure_carrier, PublishMode::Replace)
        .unwrap();
    authority.decode_checkpoint(&configure_carrier).unwrap();
    let before = authority.test_checkpoint_import_attempts();
    assert!(matches!(
        authority.retained_finality(&directory, &transaction),
        Err(crate::managed::Error::Invalid(message))
            if message == "original native operation transaction absent from certified carrier"
    ));
    assert_eq!(authority.test_checkpoint_import_attempts(), before);
    let standalone = crate::managed::native_operation::retained_carrier(
        &directory,
        authority.config.network_id,
        authority.config.chain.as_str(),
        &transaction,
    )
    .unwrap_err();
    assert_eq!(
        authority
            .retained_finality(&directory, &transaction)
            .unwrap_err()
            .to_string(),
        standalone.to_string()
    );
    directory
        .write_atomic("carrier.nrt", &carrier, PublishMode::Replace)
        .unwrap();
    assert_eq!(
        authority
            .retained_finality(&directory, &transaction)
            .unwrap(),
        Some(retained)
    );
    assert_eq!(authority.test_checkpoint_import_attempts(), before);

    // Actual changed and absent files still refuse independently of the warm original image.
    directory
        .write_atomic("carrier.nrt", &[0xff], PublishMode::Replace)
        .unwrap();
    let expected_error = crate::managed::native_operation::retained_carrier(
        &directory,
        authority.config.network_id,
        authority.config.chain.as_str(),
        &transaction,
    )
    .unwrap_err()
    .to_string();
    // A retained memo triggers one clear-all cold retry; the next refusal starts empty.
    for expected_imports in [2, 1] {
        let before = authority.test_checkpoint_import_attempts();
        assert_eq!(
            authority
                .retained_finality(&directory, &transaction)
                .unwrap_err()
                .to_string(),
            expected_error
        );
        assert_eq!(
            authority.test_checkpoint_import_attempts(),
            before + expected_imports
        );
    }
    directory
        .write_atomic("carrier.nrt", &carrier, PublishMode::Replace)
        .unwrap();
    assert_eq!(
        authority
            .retained_finality(&directory, &transaction)
            .unwrap(),
        Some(retained)
    );
    std::fs::remove_file(directory.path().join("carrier.nrt")).unwrap();
    let before = authority.test_checkpoint_import_attempts();
    assert!(
        authority
            .retained_finality(&directory, &transaction)
            .unwrap()
            .is_none()
    );
    assert_eq!(authority.test_checkpoint_import_attempts(), before);
    directory
        .write_atomic("carrier.nrt", &carrier, PublishMode::CreateNew)
        .unwrap();
    let restored = fixture
        .owner
        .retained_initial_prerequisite(deadline)
        .unwrap();
    assert_same(&restored.enrollment, &expected.enrollment);
    assert_eq!(fixture.native.chain.height(), 4);
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

#[test]
fn prerequisite_epoch_workspace_keeps_original_phase_source_refusal_and_same_source_retry() {
    let _guard = crate::managed::native_test_guard();
    let fixture = Fixture::enrolled(4_000);
    let mut peers = UnavailablePeers::start(&fixture.prepared);
    let deadline = fixture.options.deadline;
    let expected = fixture
        .owner
        .retained_initial_prerequisite(deadline)
        .unwrap();
    let paths = retained_paths(&fixture);
    let mut validation = EpochValidationScope::new();
    let mut imports = CheckpointImports::new(&fixture.owner.authority, Some(&mut validation));
    let configured = fixture
        .owner
        .read_configuration_with_imports(deadline, &mut imports)
        .unwrap();
    let RetainedConfiguration {
        owner: _,
        original,
        signed,
        carrier,
        policy,
        finalized,
    } = configured;
    drop((original, signed, carrier));
    // Same retained workspace, independently selected Initial original and observed wallet.
    // Mutation occurs after Configure succeeded, at the genuine synchronous phase boundary.
    let (selected, interval) = fixture
        .owner
        .inspect_initial_selection_with_imports(&policy, &mut imports)
        .unwrap()
        .unwrap();
    let directory = PrivateDirectory::open_exact(selected.directory().path()).unwrap();
    let carrier = directory.read("carrier.nrt", MAX_CHECKPOINT_BYTES).unwrap();
    directory
        .write_atomic("carrier.nrt", &[0xff], PublishMode::Replace)
        .unwrap();
    let error = fixture
        .owner
        .verify_retained_enrollment_with_imports(
            CustodyPurpose::InitialEnroll,
            &policy,
            Some(interval),
            &finalized,
            selected,
            deadline,
            &mut imports,
        )
        .err()
        .expect("changed carrier must refuse");
    assert!(
        matches!(error, crate::managed::Error::Invalid(message) if message == "invalid retained native operation checkpoint")
    );
    directory
        .write_atomic("carrier.nrt", &carrier, PublishMode::Replace)
        .unwrap();
    let restored = fixture
        .owner
        .initial_prerequisite_after_configuration_with_imports(
            policy.clone(),
            finalized,
            deadline,
            &mut imports,
        )
        .unwrap();
    assert_eq!(restored.policy, expected.policy);
    assert_same(&restored.enrollment, &expected.enrollment);

    // The actual initial observed wallet callback cannot be skipped by a matching epoch.
    let (path, name, maximum) = &paths[7];
    assert_eq!(*name, "operation.json");
    let wallet = PrivateDirectory::open_exact(path).unwrap();
    let before = wallet.read(name, *maximum).unwrap();
    wallet
        .write_atomic(name, &[0xff], PublishMode::Replace)
        .unwrap();
    let (refused, configurations, wallets) = counted(|| {
        fixture
            .owner
            .initial_prerequisite_after_configuration_with_imports(
                policy.clone(),
                finalized,
                deadline,
                &mut imports,
            )
    });
    assert!(refused.is_err());
    assert_eq!(configurations, 0);
    assert_eq!(wallets, 1);
    wallet
        .write_atomic(name, &before, PublishMode::Replace)
        .unwrap();
    let (restored, configurations, wallets) = counted(|| {
        fixture
            .owner
            .initial_prerequisite_after_configuration_with_imports(
                policy.clone(),
                finalized,
                deadline,
                &mut imports,
            )
    });
    assert_eq!(configurations, 0);
    assert_eq!(wallets, 1);
    assert_same(&restored.unwrap().enrollment, &expected.enrollment);
    drop(imports);
    drop(validation);
    let (fresh, configurations, wallets) =
        counted(|| fixture.owner.retained_initial_prerequisite(deadline));
    assert_eq!((configurations, wallets), (1, 1));
    assert_same(&fresh.unwrap().enrollment, &expected.enrollment);
    assert!(peers.requests.lock().unwrap().is_empty());
    assert_eq!(fixture.native.chain.height(), 4);
    peers.finish();
}

#[test]
fn prerequisite_epoch_workspace_preserves_finite_outer_admission_and_custody_retry() {
    use norito::core::DecodeBudgetContext;
    fn limits(allocation: usize) -> norito::DecodeLimits {
        norito::DecodeLimits::new(
            1024 * 1024,
            MAX_CHECKPOINT_BYTES,
            8 * 1024 * 1024,
            allocation,
            64,
        )
    }
    fn independent(
        owner: &ManagedStreamTokenCustody,
        deadline: Instant,
    ) -> Result<RetainedInitialPrerequisite> {
        // The original entry sequence, using the same canonical bodies with no borrowed scope.
        require_deadline(deadline)?;
        owner.authority.validate_profile()?;
        let (policy, configured) = owner.retained_configuration(deadline)?;
        owner.initial_prerequisite_after_configuration(policy, configured, deadline)
    }
    let _guard = crate::managed::native_test_guard();
    let fixture = Fixture::enrolled(4_000);
    let mut peers = UnavailablePeers::start(&fixture.prepared);
    let deadline = fixture.options.deadline;
    let warm = fixture
        .owner
        .retained_initial_prerequisite(deadline)
        .unwrap();
    let ceiling = 256 * 1024 * 1024;
    let baseline_budget = DecodeBudgetContext::new(limits(ceiling));
    let expected = baseline_budget
        .with(|| independent(&fixture.owner, deadline))
        .unwrap();
    let charge = baseline_budget.consumed_allocated_bytes();
    assert!(charge > 0 && charge < ceiling as u64);
    let strict = DecodeBudgetContext::new(limits(usize::try_from(charge).unwrap()));
    let (actual, configurations, wallets) =
        counted(|| strict.with(|| fixture.owner.retained_initial_prerequisite(deadline)));
    let actual = actual.unwrap();
    assert_eq!((configurations, wallets), (1, 1));
    assert_eq!(strict.consumed_allocated_bytes(), charge);
    assert_eq!(actual.policy, expected.policy);
    assert_same(&actual.enrollment, &expected.enrollment);
    assert_same(&actual.enrollment, &warm.enrollment);
    // These bounded caller refusals stop before any signing, effect or peer request.
    for allocation in [0, 1] {
        let expected_budget = DecodeBudgetContext::new(limits(allocation));
        let expected = expected_budget
            .with(|| independent(&fixture.owner, deadline))
            .err()
            .expect("original finite owner refuses")
            .to_string();
        let actual_budget = DecodeBudgetContext::new(limits(allocation));
        let actual = actual_budget
            .with(|| fixture.owner.retained_initial_prerequisite(deadline))
            .err()
            .expect("scoped finite owner refuses")
            .to_string();
        assert_eq!(actual, expected);
        assert_eq!(
            actual_budget.consumed_allocated_bytes(),
            expected_budget.consumed_allocated_bytes()
        );
        let retry = fixture
            .owner
            .retained_initial_prerequisite(deadline)
            .unwrap();
        assert_same(&retry.enrollment, &warm.enrollment);
    }
    assert!(peers.requests.lock().unwrap().is_empty());
    assert_eq!(fixture.native.chain.height(), 4);
    peers.finish();
}
