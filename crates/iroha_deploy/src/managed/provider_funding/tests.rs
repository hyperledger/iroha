//! Bounded retained-claim tests. Codec checkpoints and partitions do not construct native evidence.
use super::*;
use crate::managed::native_operation::now_ms;
use crate::managed::native_operation::test_support::{UnavailablePeers, native_fixture::policy};
use iroha_data_model::{
    sorafs::reserve::{ReserveLifecycleStage, ReserveProviderAccountV1},
    transaction::FeePaymentIntent,
};
use iroha_primitives::numeric::{Quantity, XorQuantity};
use iroha_wallet::operations::BoundedTransactionOptions;
use std::{collections::BTreeMap, time::Duration};

pub(super) fn fixture() -> (
    tempfile::TempDir,
    PreparedLocalnet,
    ProviderFundingBootstrap,
) {
    let root = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet(
        "automatic-provider-funding",
        &root.path().join("generation"),
        &ports,
    )
    .unwrap();
    let owner = ProviderFundingBootstrap::open(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
    )
    .unwrap();
    (root, prepared, owner)
}
pub(super) fn options() -> BoundedTransactionOptions {
    BoundedTransactionOptions {
        fee_payment: FeePaymentIntent::authority(Vec::new(), None),
        max_total_fees: BTreeMap::new(),
        deadline: Instant::now() + Duration::from_secs(180),
    }
}
fn claims(owner: &ProviderFundingBootstrap, balance: &str) -> Original {
    let plan = owner.plan().unwrap();
    let policy = policy(&owner.authority);
    let now = now_ms().unwrap();
    let partition = ReserveProviderAccountV1 {
        terms: plan.reserve_terms().clone(),
        policy_digest: policy.digest().unwrap(),
        revision: 1,
        reserve_balance: balance.parse().unwrap(),
        debt_principal: XorQuantity::zero(),
        accrued_interest: XorQuantity::zero(),
        credit_cap: XorQuantity::zero(),
        lifecycle_stage: ReserveLifecycleStage::Warning,
        days_past_due: 0,
        pending_movements: 0,
        open_appeals: 0,
        rent_charged_through_unix: now / 1000,
        interest_accrued_at_unix: now / 1000,
        updated_at_unix: now / 1000,
    };
    let economics =
        provider_economics::derive_retained(&plan, &policy, &partition, None, plan.pricing(), now)
            .unwrap();
    Original {
        network_id: plan.network_id(),
        policy,
        partition,
        pricing: plan.pricing().clone(),
        observed_block_time_ms: now,
        economics,
        movement_id: [0x62; 32],
        fees: Fees::from_options(&options()).unwrap(),
        checkpoint: vec![0xA5; 16 * 1024],
    }
}
fn selected(original: &Original, kind: Stage) -> SelectedStage {
    let mut partition = original.partition.clone();
    let top_up = !original.economics.top_up.is_zero();
    match kind {
        Stage::Approval => {
            partition.revision += 1;
            partition.pending_movements = 1;
        }
        Stage::Credit => {
            partition.revision += if top_up { 2 } else { 0 };
            partition.reserve_balance = partition
                .reserve_balance
                .checked_add(&original.economics.top_up)
                .unwrap();
        }
    }
    let credit = (kind == Stage::Credit).then(|| {
        iroha_data_model::sorafs::pricing::ProviderCreditRecord::new(
            partition.terms.provider_id,
            original.economics.available_credit.clone(),
            partition.reserve_balance.as_quantity().clone(),
            original.economics.price_bond.clone(),
            original.economics.expected_settlement.clone(),
            original.economics.onboarding_epoch,
            original.economics.observed_epoch,
            Default::default(),
        )
    });
    SelectedStage {
        stage: kind,
        original: original.digest().unwrap(),
        partition,
        checkpoint: vec![0xA5; 16 * 1024],
        credit,
    }
}

#[test]
fn automatic_amounts_keep_underwriting_distinct_from_price_bond_and_overfunded_balance() {
    let _guard = crate::managed::native_test_guard();
    let (_root, _prepared, owner) = fixture();
    let plan = owner.plan().unwrap();
    let original = claims(&owner, "0");
    original.validate(&plan).unwrap();
    assert_eq!(
        original.economics.top_up,
        "24".parse::<XorQuantity>().unwrap()
    );
    assert_eq!(
        original.economics.price_bond,
        "0.75".parse::<Quantity>().unwrap()
    );
    assert_eq!(original.top_up().unwrap().amount, original.economics.top_up);
    let approval = selected(&original, Stage::Approval);
    approval.validate(Stage::Approval, &original).unwrap();
    assert_eq!(
        approval
            .approval(&original)
            .unwrap()
            .expected_provider_revision,
        2
    );
    let credit = selected(&original, Stage::Credit);
    let intent = credit.credit(&original).unwrap();
    assert_eq!(intent.partition.revision, 3);
    assert_eq!(intent.record.bonded, Quantity::from(24u64));
    assert_eq!(
        intent.record.onboarding_epoch,
        original.economics.onboarding_epoch
    );
    assert_eq!(
        intent.record.last_settlement_epoch,
        original.economics.observed_epoch
    );
    // Native Request/Decide lazily project policy digest and credit cap without an extra
    // revision. Structural intent admits those actual native changes rather than adding a CAS.
    let mut lagged = original.clone();
    lagged.partition.policy_digest = [0x71; 32];
    lagged.validate(&plan).unwrap();
    let mut projected = selected(&lagged, Stage::Approval);
    projected.partition.policy_digest = lagged.policy.digest().unwrap();
    projected.partition.credit_cap = "1".parse().unwrap();
    projected.partition.updated_at_unix += 1;
    projected.validate(Stage::Approval, &lagged).unwrap();
    let overfunded = claims(&owner, "32");
    overfunded.validate(&plan).unwrap();
    assert!(overfunded.top_up().is_none());
    let funded = selected(&overfunded, Stage::Credit)
        .credit(&overfunded)
        .unwrap();
    assert_eq!(funded.partition.revision, 1);
    assert_eq!(funded.record.bonded, Quantity::from(32u64));
    assert!(
        selected(&overfunded, Stage::Approval)
            .validate(Stage::Approval, &overfunded)
            .is_err()
    );
}

#[test]
fn original_and_create_only_stage_reopen_preserve_full_inputs_and_reject_substitution() {
    let _guard = crate::managed::native_test_guard();
    let (_root, _prepared, owner) = fixture();
    let plan = owner.plan().unwrap();
    let original = claims(&owner, "0");
    let directory = owner.authority.directory.ensure_child("funding").unwrap();
    original::publish(&directory, &plan, &original).unwrap();
    assert!(original::publish(&directory, &plan, &original).is_err());
    let retained = original::read(&directory, &plan).unwrap().unwrap();
    assert_eq!(retained.checkpoint.len(), 16 * 1024);
    assert!(
        owner.validate_original(&plan, &retained).is_err(),
        "codec claims cannot authenticate a native checkpoint"
    );
    let approval = selected(&original, Stage::Approval);
    stage::publish(&directory, Stage::Approval, &original, &approval).unwrap();
    assert!(stage::publish(&directory, Stage::Approval, &original, &approval).is_err());
    let restored = stage::read(&directory, Stage::Approval, &original)
        .unwrap()
        .unwrap();
    assert_eq!(restored.partition, approval.partition);
    for field in 0..5 {
        let mut changed = original.clone();
        match field {
            0 => changed.economics.top_up = "25".parse().unwrap(),
            1 => changed.partition.open_appeals = 1,
            2 => changed.observed_block_time_ms += 1000,
            3 => changed.pricing.version += 1,
            _ => changed.movement_id = [0; 32],
        };
        assert!(changed.validate(&plan).is_err());
    }
    let mut changed = original.clone();
    changed.movement_id = [0x63; 32];
    changed.validate(&plan).unwrap();
    assert!(restored.validate(Stage::Approval, &changed).is_err());
    for field in 0..4 {
        let mut changed = selected(&original, Stage::Credit);
        match field {
            0 => changed.partition.revision += 1,
            1 => changed.partition.reserve_balance = "25".parse().unwrap(),
            2 => changed.credit.as_mut().unwrap().onboarding_epoch += 1,
            _ => changed.credit = None,
        };
        assert!(changed.validate(Stage::Credit, &original).is_err());
    }
    let mut opts = original
        .fees
        .options(Instant::now() + Duration::from_secs(15));
    opts.max_total_fees.insert(
        original.policy.asset_definition.clone(),
        Quantity::from(1u64),
    );
    assert!(
        original
            .matches(&plan, &original.policy, &Fees::from_options(&opts).unwrap())
            .is_err()
    );
    // A new I/O deadline is deliberately absent from semantic identity. Changing full
    // spending intent still refuses, including Authority payment details distinct from maxima.
    let before = original.digest().unwrap();
    let later = original
        .fees
        .options(Instant::now() + Duration::from_secs(30));
    original
        .matches(
            &plan,
            &original.policy,
            &Fees::from_options(&later).unwrap(),
        )
        .unwrap();
    assert_eq!(before, original.digest().unwrap());
    let mut changed = original.policy.clone();
    changed.grace_period_days += 1;
    assert!(original.matches(&plan, &changed, &original.fees).is_err());
}

#[test]
fn absent_recovery_and_unavailable_native_cut_create_no_child_original_or_dispatch() {
    let _guard = crate::managed::native_test_guard();
    let (_root, prepared, mut owner) = fixture();
    let mut peers = UnavailablePeers::start(&prepared);
    assert!(
        owner
            .run(
                Instant::now() + Duration::from_secs(15),
                Mode::Recover,
                None
            )
            .is_err()
    );
    assert!(peers.requests.lock().unwrap().is_empty());
    let policy = policy(&owner.authority);
    let error = owner
        .select_economics(
            &policy,
            &Fees::from_options(&options()).unwrap(),
            options().deadline,
        )
        .err()
        .unwrap();
    assert!(
        error
            .to_string()
            .contains("cannot read original genesis result"),
        "{error}"
    );
    let directory = owner.authority.directory.open_child("funding").unwrap();
    require_empty(&directory).unwrap();
    peers.finish();
    assert!(
        peers
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|r| r.method == "GET")
    );
    for name in [
        "reserve-top-up-request",
        "reserve-top-up-approval",
        "initial-provider-credit",
        "provider-capacity-declaration",
    ] {
        assert!(
            !owner
                .authority
                .directory
                .path()
                .parent()
                .unwrap()
                .join(name)
                .exists()
        );
    }
}

#[test]
fn selected_recovery_distinguishes_absent_empty_and_dirty_without_http() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, prepared, mut owner) = fixture();
    let policy = policy(&owner.authority);
    let options = options();
    let fees = Fees::from_options(&options).unwrap();
    let mut peers =
        crate::managed::native_operation::test_support::UnavailablePeers::start(&prepared);
    assert!(
        owner
            .recover_selected_if_present(&policy, &fees, options.deadline)
            .unwrap()
            .is_none()
    );
    assert!(!owner.authority.directory.path().join("funding").exists());
    let directory = owner.authority.directory.ensure_child("funding").unwrap();
    assert!(
        owner
            .recover_selected_if_present(&policy, &fees, options.deadline)
            .unwrap()
            .is_none()
    );
    require_empty(&directory).unwrap();
    directory
        .write_atomic("incomplete.nrt", &[1], iroha_fs::PublishMode::CreateNew)
        .unwrap();
    assert!(
        owner
            .recover_selected_if_present(&policy, &fees, options.deadline)
            .is_err()
    );
    assert!(!directory.path().join("transaction").exists());
    assert_eq!(
        directory.read("incomplete.nrt", 1).unwrap().as_slice(),
        &[1]
    );
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

#[test]
fn only_incomplete_unsigned_transition_is_classified_as_unprepared() {
    assert_eq!(recover_progress::<u8>(Ok(Some(7))).unwrap(), Some(7));
    assert_eq!(recover_progress::<u8>(Ok(None)).unwrap(), None);
    assert!(
        recover_progress::<u8>(Err(
            super::super::ManagedBootstrapFailure::TransitionPending.into()
        ))
        .unwrap()
        .is_none()
    );
    for error in [
        super::super::ManagedBootstrapFailure::PayloadExpired,
        super::super::ManagedBootstrapFailure::AuthorizationExpired,
        super::super::ManagedBootstrapFailure::EpochLimit,
    ] {
        assert!(recover_progress::<u8>(Err(error.into())).is_err());
    }
    assert!(recover_progress::<u8>(Err(invalid("lost committed wallet custody"))).is_err());
}

#[test]
fn incomplete_funding_refuses_later_material_without_http_or_custody_mutation() {
    let _guard = crate::managed::native_test_guard();
    let (_root, prepared, mut owner) = fixture();
    let mut peers = UnavailablePeers::start(&prepared);
    owner.authority.directory.ensure_child("funding").unwrap();
    owner
        .require_no_later_material(FundingStep::Request)
        .unwrap();
    let later = ServiceAuthority::open_provider(
        &prepared,
        owner.authority.provider_id().unwrap(),
        ProviderPurpose::InitialProviderCredit,
    )
    .unwrap();
    let directory = later.directory.ensure_child("install").unwrap();
    drop(later);
    owner
        .require_no_later_material(FundingStep::Request)
        .unwrap();
    directory
        .write_atomic("original.nrt", &[0xA5], iroha_fs::PublishMode::CreateNew)
        .unwrap();
    assert!(
        owner
            .require_no_later_material(FundingStep::Request)
            .is_err()
    );
    assert!(
        owner
            .require_no_later_material(FundingStep::Approval)
            .is_err()
    );
    assert_eq!(
        directory.read("original.nrt", 1).unwrap().as_slice(),
        &[0xA5]
    );
    assert!(!directory.path().join("attempts").exists());
    let policy = policy(&owner.authority);
    assert!(
        owner
            .select_economics(
                &policy,
                &Fees::from_options(&options()).unwrap(),
                options().deadline
            )
            .is_err()
    );
    require_empty(&owner.authority.directory.open_child("funding").unwrap()).unwrap();
    let fees = Fees::from_options(&options()).unwrap();
    assert!(
        owner
            .recover_selected_if_present(&policy, &fees, options().deadline)
            .is_err()
    );
    assert!(
        owner
            .recover_local_selected_if_present(&policy, &fees, options().deadline)
            .is_err()
    );
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

#[test]
fn unfinished_parent_refuses_held_later_purpose_and_preserves_same_source_retry() {
    let _guard = crate::managed::native_test_guard();
    let (_root, prepared, owner) = fixture();
    let funding = owner.authority.directory.ensure_child("funding").unwrap();
    let original_names = funding.entries(3).unwrap();
    // Retain the genuine named lock itself while dropping the other original authority fields
    // before a fresh authority is opened by the refusal gate.
    let (held_lock, install) = {
        let later = ServiceAuthority::open_provider(
            &prepared,
            owner.authority.provider_id().unwrap(),
            ProviderPurpose::InitialProviderCredit,
        )
        .unwrap();
        let install = later.directory.ensure_child("install").unwrap();
        (later._lock, install)
    };
    for step in [FundingStep::Request, FundingStep::Approval] {
        assert_eq!(
            owner.unprepared(step).unwrap_err().to_string(),
            "another managed native operation holds this generation"
        );
    }
    assert_eq!(funding.entries(3).unwrap(), original_names);
    require_empty(&install).unwrap();
    drop(held_lock);
    for step in [FundingStep::Request, FundingStep::Approval] {
        let ProviderFundingProgress::Unprepared {
            step: returned,
            status,
        } = owner.unprepared(step).unwrap()
        else {
            panic!("original incomplete funding report")
        };
        assert_eq!(returned, step);
        assert_eq!(status, OperationStatus::Absent);
    }
    assert_eq!(funding.entries(3).unwrap(), original_names);
    install
        .write_atomic("original.nrt", &[0xA5], iroha_fs::PublishMode::CreateNew)
        .unwrap();
    for step in [FundingStep::Request, FundingStep::Approval] {
        assert!(owner.unprepared(step).is_err());
    }
    assert_eq!(install.read("original.nrt", 1).unwrap().as_slice(), &[0xA5]);
    assert!(!install.path().join("attempts").exists());
    assert_eq!(funding.entries(3).unwrap(), original_names);
}
