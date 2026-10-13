//! Original generated parent custody and exact wallet child recovery; no native success fixtures.
use super::*;
use crate::operations::setup_test_support::{account, service};
use std::{sync::atomic::Ordering, time::Duration};

fn selection(config: &Config) -> MusubiNamespaceBindingSelection {
    super::super::tests::request(config, current_unix_ms().unwrap()).selection
}
fn fee() -> FeePaymentIntent {
    FeePaymentIntent::authority(Vec::new(), None)
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(60)
}

#[test]
fn generation_parent_is_create_only_exact_and_never_repaired_on_open() {
    let (service, transport) = service();
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("parent");
    let selected = selection(&service.config);
    assert!(
        service
            .open_musubi_namespace_binding_parent(&path, &selected, &fee())
            .is_err()
    );
    assert!(!path.exists());
    service
        .initialize_musubi_namespace_binding_parent(&path, &selected, &fee())
        .unwrap();
    let original = std::fs::read(path.join("operation.json")).unwrap();
    assert!(
        service
            .initialize_musubi_namespace_binding_parent(&path, &selected, &fee())
            .is_err()
    );
    let parent = service
        .open_musubi_namespace_binding_parent(&path, &selected, &fee())
        .unwrap();
    assert!(parent.inspect(deadline()).unwrap().is_none());
    assert!(
        service
            .open_musubi_namespace_binding_parent(&path, &selected, &fee())
            .is_err()
    );
    drop(parent);
    let mut wrong = selected.clone();
    wrong.owner = account(199);
    assert!(
        service
            .open_musubi_namespace_binding_parent(&path, &wrong, &fee())
            .is_err()
    );
    let mut wrong = selected.clone();
    wrong.expected_policy_revision += 1;
    assert!(
        service
            .open_musubi_namespace_binding_parent(&path, &wrong, &fee())
            .is_err()
    );
    let wrong = FeePaymentIntent::authority(Vec::new(), std::num::NonZeroU64::new(1));
    assert!(
        service
            .open_musubi_namespace_binding_parent(&path, &selected, &wrong)
            .is_err()
    );
    assert_eq!(
        std::fs::read(path.join("operation.json")).unwrap(),
        original
    );
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
    std::fs::remove_file(path.join("operation.json")).unwrap();
    assert!(
        service
            .open_musubi_namespace_binding_parent(&path, &selected, &fee())
            .is_err()
    );
    assert!(!path.join("operation.json").exists());
}
#[test]
fn parent_503_reopen_retains_one_original_utc_and_exact_child_once() {
    let (service, transport) = service();
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("parent");
    let selected = selection(&service.config);
    service
        .initialize_musubi_namespace_binding_parent(&path, &selected, &fee())
        .unwrap();
    *transport.journal.lock().unwrap() = Some(path.join(name("transaction", 1)));
    let utc = current_unix_ms().unwrap() + 50_000;
    let parent = service
        .open_musubi_namespace_binding_parent(&path, &selected, &fee())
        .unwrap();
    assert_eq!(
        parent.advance(utc, deadline()).unwrap().status,
        OperationStatus::Pending
    );
    assert_eq!(
        parent
            .audit(deadline())
            .unwrap()
            .last()
            .unwrap()
            .authorization
            .deadline_ms,
        utc
    );
    let authorization = std::fs::read(path.join(name("authorization", 1))).unwrap();
    let marker = std::fs::read(path.join(name("child", 1))).unwrap();
    let signed = std::fs::read(path.join(name("transaction", 1)).join("operation.json")).unwrap();
    let exposure =
        std::fs::read(path.join(name("transaction", 1)).join("submission.json")).unwrap();
    drop(parent);
    for _ in 0..2 {
        let parent = service
            .open_musubi_namespace_binding_parent(&path, &selected, &fee())
            .unwrap();
        assert_eq!(
            parent.advance(utc + 60_000, deadline()).unwrap().status,
            OperationStatus::Pending
        );
        assert_eq!(
            parent
                .audit(deadline())
                .unwrap()
                .last()
                .unwrap()
                .authorization
                .deadline_ms,
            utc
        );
        assert_eq!(
            parent.inspect(deadline()).unwrap().unwrap().phase(),
            NativePreparationPhase::Signed
        );
    }
    assert_eq!(transport.quotes.load(Ordering::SeqCst), 1);
    assert_eq!(transport.submissions.load(Ordering::SeqCst), 1);
    assert_eq!(
        std::fs::read(path.join(name("authorization", 1))).unwrap(),
        authorization
    );
    assert_eq!(std::fs::read(path.join(name("child", 1))).unwrap(), marker);
    assert_eq!(
        std::fs::read(path.join(name("transaction", 1)).join("operation.json")).unwrap(),
        signed
    );
    assert_eq!(
        std::fs::read(path.join(name("transaction", 1)).join("submission.json")).unwrap(),
        exposure
    );
    let calls = transport.requests.load(Ordering::SeqCst);
    std::fs::remove_dir_all(path.join(name("transaction", 1))).unwrap();
    assert!(
        service
            .open_musubi_namespace_binding_parent(&path, &selected, &fee())
            .is_err()
    );
    assert!(!path.join(name("transaction", 1)).exists());
    assert_eq!(transport.requests.load(Ordering::SeqCst), calls);
}
#[test]
fn unmarked_later_wallet_or_unknown_parent_material_refuses_before_http() {
    let (service, transport) = service();
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("parent");
    let selected = selection(&service.config);
    service
        .initialize_musubi_namespace_binding_parent(&path, &selected, &fee())
        .unwrap();
    let parent = service
        .open_musubi_namespace_binding_parent(&path, &selected, &fee())
        .unwrap();
    let now = current_unix_ms().unwrap();
    let authorization = Authorization {
        ordinal: 1,
        predecessor_retirement: None,
        selected_at_ms: now,
        deadline_ms: now + 50_000,
    };
    parent
        .directory
        .write_atomic(
            name("authorization", 1),
            &encode_bounded(&authorization, MAX_PARENT_BYTES).unwrap(),
            PublishMode::CreateNew,
        )
        .unwrap();
    parent.anchor(&authorization).unwrap();
    let request = parent.request(&authorization, deadline()).unwrap();
    service
        .prepare_musubi_namespace_binding(&request, &path.join(name("transaction", 1)))
        .unwrap();
    let calls = transport.requests.load(Ordering::SeqCst);
    assert!(parent.inspect(deadline()).is_err());
    assert!(parent.advance(now + 60_000, deadline()).is_err());
    assert!(!path.join(name("child", 1)).exists());
    assert_eq!(transport.requests.load(Ordering::SeqCst), calls);
    drop(parent);
    assert!(
        service
            .open_musubi_namespace_binding_parent(&path, &selected, &fee())
            .is_err()
    );
    let other = root.path().join("unknown");
    service
        .initialize_musubi_namespace_binding_parent(&other, &selected, &fee())
        .unwrap();
    let directory = PrivateDirectory::open(&other).unwrap();
    directory
        .write_atomic("foreign.nrt", b"not authority", PublishMode::CreateNew)
        .unwrap();
    assert!(
        service
            .open_musubi_namespace_binding_parent(&other, &selected, &fee())
            .is_err()
    );
}
#[test]
fn expired_unsigned_authorization_needs_a_new_valid_caller_window() {
    let (service, transport) = service();
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("parent");
    let selected = selection(&service.config);
    service
        .initialize_musubi_namespace_binding_parent(&path, &selected, &fee())
        .unwrap();
    let parent = service
        .open_musubi_namespace_binding_parent(&path, &selected, &fee())
        .unwrap();
    let now = current_unix_ms().unwrap();
    let authorization = Authorization {
        ordinal: 1,
        predecessor_retirement: None,
        selected_at_ms: now - 100,
        deadline_ms: now - 1,
    };
    parent
        .directory
        .write_atomic(
            name("authorization", 1),
            &encode_bounded(&authorization, MAX_PARENT_BYTES).unwrap(),
            PublishMode::CreateNew,
        )
        .unwrap();
    let original = std::fs::read(path.join(name("authorization", 1))).unwrap();
    assert!(parent.advance(now - 1, deadline()).is_err());
    assert!(!path.join(name("transaction", 1)).exists());
    assert!(!path.join(name("child", 1)).exists());
    drop(parent);
    let reopened = service
        .open_musubi_namespace_binding_parent(&path, &selected, &fee())
        .unwrap();
    assert!(reopened.advance(now - 1, deadline()).is_err());
    assert_eq!(
        std::fs::read(path.join(name("authorization", 1))).unwrap(),
        original
    );
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
}
#[test]
fn original_request_only_crash_recovers_same_hash_before_any_quote() {
    let (service, transport) = service();
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("parent");
    let selected = selection(&service.config);
    service
        .initialize_musubi_namespace_binding_parent(&path, &selected, &fee())
        .unwrap();
    let parent = service
        .open_musubi_namespace_binding_parent(&path, &selected, &fee())
        .unwrap();
    let now = current_unix_ms().unwrap();
    let authorization = Authorization {
        ordinal: 1,
        predecessor_retirement: None,
        selected_at_ms: now,
        deadline_ms: now + 50_000,
    };
    parent
        .directory
        .write_atomic(
            name("authorization", 1),
            &encode_bounded(&authorization, MAX_PARENT_BYTES).unwrap(),
            PublishMode::CreateNew,
        )
        .unwrap();
    parent.anchor(&authorization).unwrap();
    let request = parent.request(&authorization, deadline()).unwrap();
    let retained = service
        .retain_musubi_namespace_binding_request(&request, &path.join(name("transaction", 1)))
        .unwrap();
    assert_eq!(
        parent
            .inspect(deadline())
            .unwrap()
            .unwrap()
            .request_sha256(),
        retained.request_sha256()
    );
    assert!(!path.join(name("child", 1)).exists());
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
    drop(parent);
    *transport.journal.lock().unwrap() = Some(path.join(name("transaction", 1)));
    let reopened = service
        .open_musubi_namespace_binding_parent(&path, &selected, &fee())
        .unwrap();
    assert_eq!(
        reopened.advance(now + 60_000, deadline()).unwrap().status,
        OperationStatus::Pending
    );
    assert_eq!(
        reopened
            .inspect(deadline())
            .unwrap()
            .unwrap()
            .request_sha256(),
        retained.request_sha256()
    );
    assert_eq!(
        reopened
            .audit(deadline())
            .unwrap()
            .last()
            .unwrap()
            .authorization
            .deadline_ms,
        authorization.deadline_ms
    );
    assert_eq!(transport.quotes.load(Ordering::SeqCst), 1);
    assert_eq!(transport.submissions.load(Ordering::SeqCst), 1);
}

#[test]
fn actual_expired_request_only_retires_once_and_commits_the_successor_chain() {
    let (service, transport) = service();
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("parent");
    let selected = selection(&service.config);
    service
        .initialize_musubi_namespace_binding_parent(&path, &selected, &fee())
        .unwrap();
    let parent = service
        .open_musubi_namespace_binding_parent(&path, &selected, &fee())
        .unwrap();
    let now = current_unix_ms().unwrap();
    let original = Authorization {
        ordinal: 1,
        predecessor_retirement: None,
        selected_at_ms: now,
        deadline_ms: now + 300,
    };
    parent
        .directory
        .write_atomic(
            name("authorization", 1),
            &encode_bounded(&original, MAX_PARENT_BYTES).unwrap(),
            PublishMode::CreateNew,
        )
        .unwrap();
    parent.anchor(&original).unwrap();
    let request = parent.request(&original, deadline()).unwrap();
    let old = path.join(name("transaction", 1));
    let prepared = service
        .retain_musubi_namespace_binding_request(&request, &old)
        .unwrap();
    assert_eq!(prepared.phase(), NativePreparationPhase::RequestOnly);
    let request_bytes = std::fs::read(old.join("preparation.json")).unwrap();
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
    drop(parent);
    let wait_bound = Instant::now() + Duration::from_secs(2);
    while current_unix_ms().unwrap() < original.deadline_ms {
        assert!(Instant::now() < wait_bound);
        std::thread::sleep(Duration::from_millis(2));
    }
    let parent = service
        .open_musubi_namespace_binding_parent(&path, &selected, &fee())
        .unwrap();
    let next = path.join(name("transaction", 2));
    *transport.journal.lock().unwrap() = Some(next.clone());
    assert_eq!(
        parent
            .advance(current_unix_ms().unwrap() + 50_000, deadline())
            .unwrap()
            .status,
        OperationStatus::Pending
    );
    let attempts = parent.audit(deadline()).unwrap();
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0].authorization.deadline_ms, original.deadline_ms);
    assert_eq!(
        attempts[0].preparation.as_ref().unwrap().phase(),
        NativePreparationPhase::Retired
    );
    let retired = attempts[0].retirement.as_ref().unwrap();
    assert_eq!(retired.request_sha256.as_deref(), prepared.request_sha256());
    assert_eq!(
        attempts[1].authorization.predecessor_retirement,
        Some(MusubiNamespaceBindingParent::digest(retired).unwrap())
    );
    assert!(!old.join("payload.json").exists() && !old.join("operation.json").exists());
    assert_eq!(
        std::fs::read(old.join("preparation.json")).unwrap(),
        request_bytes
    );
    assert_eq!(transport.quotes.load(Ordering::SeqCst), 1);
    assert_eq!(transport.submissions.load(Ordering::SeqCst), 1);
    let signed = std::fs::read(next.join("operation.json")).unwrap();
    drop(parent);
    let reopened = service
        .open_musubi_namespace_binding_parent(&path, &selected, &fee())
        .unwrap();
    assert_eq!(
        reopened
            .advance(current_unix_ms().unwrap() + 59_000, deadline())
            .unwrap()
            .status,
        OperationStatus::Pending
    );
    assert_eq!(std::fs::read(next.join("operation.json")).unwrap(), signed);
    assert!(!path.join(name("authorization", 3)).exists());
    assert_eq!(transport.submissions.load(Ordering::SeqCst), 1);
    drop(reopened);
    std::fs::remove_dir_all(&old).unwrap();
    assert!(
        service
            .open_musubi_namespace_binding_parent(&path, &selected, &fee())
            .is_err(),
        "even retired historical children cannot disappear"
    );
}

#[test]
fn complete_unsigned_chain_cannot_exceed_64_or_ignore_holes_and_wrong_predecessors() {
    let (service, transport) = service();
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("parent");
    let selected = selection(&service.config);
    service
        .initialize_musubi_namespace_binding_parent(&path, &selected, &fee())
        .unwrap();
    let parent = service
        .open_musubi_namespace_binding_parent(&path, &selected, &fee())
        .unwrap();
    let start = current_unix_ms().unwrap() - 100_000;
    let mut previous = None;
    // Pure retained custody specimens: every retired attempt has no wallet child or HTTP.
    for ordinal in 1..=MAX_ATTEMPTS {
        let selected_at_ms = start + u64::from(ordinal) * 1_000;
        let original = Authorization {
            ordinal,
            predecessor_retirement: previous,
            selected_at_ms,
            deadline_ms: selected_at_ms + 1,
        };
        parent
            .directory
            .write_atomic(
                name("authorization", ordinal),
                &encode_bounded(&original, MAX_PARENT_BYTES).unwrap(),
                PublishMode::CreateNew,
            )
            .unwrap();
        parent.anchor(&original).unwrap();
        let retired = Retirement {
            ordinal,
            authorization_sha256: MusubiNamespaceBindingParent::digest(&original).unwrap(),
            request_sha256: None,
            retired_at_ms: original.deadline_ms,
        };
        parent
            .directory
            .write_atomic(
                name("retirement", ordinal),
                &encode_bounded(&retired, MAX_PARENT_BYTES).unwrap(),
                PublishMode::CreateNew,
            )
            .unwrap();
        previous = Some(MusubiNamespaceBindingParent::digest(&retired).unwrap());
    }
    assert_eq!(
        parent.audit(deadline()).unwrap().len(),
        usize::from(MAX_ATTEMPTS)
    );
    let names = parent.directory.entries(MAX_ENTRIES).unwrap();
    assert!(
        parent
            .advance(current_unix_ms().unwrap() + 50_000, deadline())
            .is_err()
    );
    assert_eq!(parent.directory.entries(MAX_ENTRIES).unwrap(), names);
    assert!(!path.join(name("authorization", 65)).exists());
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
    let second = path.join(name("authorization", 2));
    let bytes = std::fs::read(&second).unwrap();
    let mut changed: Authorization = decode_bounded(&bytes, MAX_PARENT_BYTES).unwrap();
    changed.predecessor_retirement = Some([0x53; 32]);
    parent
        .directory
        .write_atomic(
            name("authorization", 2),
            &encode_bounded(&changed, MAX_PARENT_BYTES).unwrap(),
            PublishMode::Replace,
        )
        .unwrap();
    assert!(parent.audit(deadline()).is_err());
    parent
        .directory
        .write_atomic(name("authorization", 2), &bytes, PublishMode::Replace)
        .unwrap();
    std::fs::remove_file(path.join(name("authorization", 1))).unwrap();
    assert!(parent.audit(deadline()).is_err());
}

#[test]
fn latest_signed_suffix_loss_cannot_reset_high_water_or_original_authorization() {
    let (service, transport) = service();
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("parent");
    let selected = selection(&service.config);
    service
        .initialize_musubi_namespace_binding_parent(&path, &selected, &fee())
        .unwrap();
    let parent = service
        .open_musubi_namespace_binding_parent(&path, &selected, &fee())
        .unwrap();
    *transport.journal.lock().unwrap() = Some(path.join(name("transaction", 1)));
    assert_eq!(
        parent
            .advance(current_unix_ms().unwrap() + 50_000, deadline())
            .unwrap()
            .status,
        OperationStatus::Pending
    );
    let anchor = std::fs::read(path.join(ANCHOR)).unwrap();
    let calls = transport.requests.load(Ordering::SeqCst);
    drop(parent);
    std::fs::remove_file(path.join(name("authorization", 1))).unwrap();
    std::fs::remove_file(path.join(name("child", 1))).unwrap();
    std::fs::remove_dir_all(path.join(name("transaction", 1))).unwrap();
    assert!(
        service
            .open_musubi_namespace_binding_parent(&path, &selected, &fee())
            .is_err()
    );
    assert_eq!(std::fs::read(path.join(ANCHOR)).unwrap(), anchor);
    assert!(!path.join(name("authorization", 1)).exists());
    assert_eq!(transport.requests.load(Ordering::SeqCst), calls);
}

#[test]
fn required_anchor_missing_foreign_or_stale_refuses_without_repair() {
    let (service, transport) = service();
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("parent");
    let selected = selection(&service.config);
    service
        .initialize_musubi_namespace_binding_parent(&path, &selected, &fee())
        .unwrap();
    let directory = PrivateDirectory::open(&path).unwrap();
    let empty = directory.read(ANCHOR, MAX_PARENT_BYTES).unwrap();
    std::fs::remove_file(path.join(ANCHOR)).unwrap();
    assert!(
        service
            .open_musubi_namespace_binding_parent(&path, &selected, &fee())
            .is_err()
    );
    assert!(!path.join(ANCHOR).exists());
    let foreign = Anchor {
        ordinal: 1,
        authorization_sha256: Some([0x19; 32]),
        child_request_sha256: None,
    };
    directory
        .write_atomic(
            ANCHOR,
            &encode_bounded(&foreign, MAX_PARENT_BYTES).unwrap(),
            PublishMode::CreateNew,
        )
        .unwrap();
    assert!(
        service
            .open_musubi_namespace_binding_parent(&path, &selected, &fee())
            .is_err()
    );
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
    directory
        .write_atomic(ANCHOR, &empty, PublishMode::Replace)
        .unwrap();
    let parent = service
        .open_musubi_namespace_binding_parent(&path, &selected, &fee())
        .unwrap();
    *transport.journal.lock().unwrap() = Some(path.join(name("transaction", 1)));
    assert_eq!(
        parent
            .advance(current_unix_ms().unwrap() + 50_000, deadline())
            .unwrap()
            .status,
        OperationStatus::Pending
    );
    let anchored = directory.read(ANCHOR, MAX_PARENT_BYTES).unwrap();
    let calls = transport.requests.load(Ordering::SeqCst);
    drop(parent);
    directory
        .write_atomic(ANCHOR, &empty, PublishMode::Replace)
        .unwrap();
    assert!(
        service
            .open_musubi_namespace_binding_parent(&path, &selected, &fee())
            .is_err()
    );
    directory
        .write_atomic(
            ANCHOR,
            &encode_bounded(&foreign, MAX_PARENT_BYTES).unwrap(),
            PublishMode::Replace,
        )
        .unwrap();
    assert!(
        service
            .open_musubi_namespace_binding_parent(&path, &selected, &fee())
            .is_err()
    );
    directory
        .write_atomic(ANCHOR, &anchored, PublishMode::Replace)
        .unwrap();
    assert!(
        service
            .open_musubi_namespace_binding_parent(&path, &selected, &fee())
            .is_ok()
    );
    assert_eq!(transport.requests.load(Ordering::SeqCst), calls);
}

#[test]
fn anchored_child_and_marker_loss_refuses_even_when_original_authorization_remains() {
    let (service, transport) = service();
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("parent");
    let selected = selection(&service.config);
    service
        .initialize_musubi_namespace_binding_parent(&path, &selected, &fee())
        .unwrap();
    let parent = service
        .open_musubi_namespace_binding_parent(&path, &selected, &fee())
        .unwrap();
    *transport.journal.lock().unwrap() = Some(path.join(name("transaction", 1)));
    assert_eq!(
        parent
            .advance(current_unix_ms().unwrap() + 50_000, deadline())
            .unwrap()
            .status,
        OperationStatus::Pending
    );
    let original = std::fs::read(path.join(name("authorization", 1))).unwrap();
    let calls = transport.requests.load(Ordering::SeqCst);
    drop(parent);
    std::fs::remove_file(path.join(name("child", 1))).unwrap();
    std::fs::remove_dir_all(path.join(name("transaction", 1))).unwrap();
    assert!(
        service
            .open_musubi_namespace_binding_parent(&path, &selected, &fee())
            .is_err()
    );
    assert_eq!(
        std::fs::read(path.join(name("authorization", 1))).unwrap(),
        original
    );
    assert_eq!(transport.requests.load(Ordering::SeqCst), calls);
}

#[test]
fn parent_fee_options_sum_full_width_limits_and_keep_numeric_overflow_cause() {
    use iroha_data_model::transaction::{FeeChargeKind, FeeChargeLimit};
    use iroha_primitives::{
        bigint::BigInt,
        numeric::{Numeric, NumericOperationError},
    };
    let (service, transport) = service();
    let root = tempfile::tempdir().unwrap();
    let selected = selection(&service.config);
    let asset: iroha_data_model::asset::AssetDefinitionId = XOR_ASSET_DEFINITION.parse().unwrap();
    let requested_deadline = deadline();
    let mut maximum_bytes = [u8::MAX; 64];
    maximum_bytes[63] = 0x7f;
    let maximum = Quantity::from_canonical_numeric(Numeric::new(
        BigInt::from_twos_bytes(&maximum_bytes).unwrap(),
        0,
    ))
    .unwrap();
    for (label, left, right, expected) in [
        (
            "full-width",
            "18446744073709551615".parse::<Quantity>().unwrap(),
            Quantity::one(),
            Some("18446744073709551616".parse::<Quantity>().unwrap()),
        ),
        ("overflow", maximum, Quantity::one(), None),
    ] {
        let intent = FeePaymentIntent::authority(
            vec![
                FeeChargeLimit::new(FeeChargeKind::Nexus, asset.clone(), left),
                FeeChargeLimit::new(FeeChargeKind::PipelineGas, asset.clone(), right),
            ],
            std::num::NonZeroU64::new(1),
        );
        intent.validate().unwrap();
        let path = root.path().join(label);
        service
            .initialize_musubi_namespace_binding_parent(&path, &selected, &intent)
            .unwrap();
        let parent = service
            .open_musubi_namespace_binding_parent(&path, &selected, &intent)
            .unwrap();
        if let Some(expected) = expected {
            let options = parent.options(requested_deadline).unwrap();
            assert_eq!(options.fee_payment, intent);
            assert_eq!(options.deadline, requested_deadline);
            assert_eq!(options.max_total_fees.len(), 1);
            assert_eq!(options.max_total_fees.get(&asset), Some(&expected));
        } else {
            let error = parent.options(requested_deadline).unwrap_err();
            assert_eq!(
                error.downcast_ref::<NumericOperationError>(),
                Some(&NumericOperationError::MantissaOverflow)
            );
            assert_eq!(error.to_string(), "namespace fee ceiling overflow");
        }
        assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
    }
}
