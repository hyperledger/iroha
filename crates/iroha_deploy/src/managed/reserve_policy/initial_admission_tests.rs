//! Genuine native absence is reused only for unsigned retention, never later preparation.
use super::*;
use crate::managed::{
    native_operation::test_support::{
        UnavailablePeers,
        native_fixture::{NativeFixture, quote_instructions},
    },
    service_bootstrap::ManagedServiceBootstrap,
};
use iroha_core::state::State;
use iroha_data_model::isi::{InstructionBox, Log, sorafs::SetSorafsReservePolicy};
use std::{
    cell::Cell,
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

fn current(
    native: &NativeFixture,
    owner: &ManagedInitialReservePolicy,
    policy: &ReserveAuthorityPolicyV1,
) -> (FinalityVerifier, VerifiedReservePolicyStateV1) {
    let cut = native.observe(&owner.authority);
    let proof = native
        .policy_proof(&owner.authority.config.account)
        .verify(
            owner.authority.config.chain.as_str(),
            owner.authority.config.network_id,
            &owner.authority.config.account,
            policy,
            State::native_world_schema_hash_v1().unwrap(),
            cut.verified_tip_ref().unwrap(),
        )
        .unwrap();
    (cut, proof)
}

#[test]
fn first_native_absence_retains_unsigned_request_but_changed_state_blocks_preparation() {
    let _resources = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet_at(
        "initial-proof-reserve",
        &temporary.path().join("generation"),
        &ports,
        crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(600);
    let mut parent = ManagedServiceBootstrap::open(&prepared).unwrap();
    let authorization = parent
        .authorize_generated_startup(deadline, Arc::new(AtomicBool::new(false)))
        .unwrap()
        .unwrap();
    let grant = authorization.test_child(Purpose::ReservePolicy).unwrap();
    let mut owner = ManagedInitialReservePolicy::open(&prepared).unwrap();
    let policy = grant.policies().network.reserve.clone();
    let mut native = NativeFixture::from_generated(&prepared, &owner.authority);
    let log = quote_instructions(
        &native,
        &owner.authority.config,
        [InstructionBox::from(Log::new(
            iroha_data_model::Level::INFO,
            "first reserve proof".into(),
        ))],
    );
    assert_eq!(native.chain.commit(vec![log]), vec![true]);
    assert_eq!(native.chain.height(), 2);
    let directory = owner.authority.directory.ensure_child("set").unwrap();
    let observations = Cell::new(0);
    let (original, mut admission) = owner
        .select_intent_using(&directory, &policy, deadline, |owner, policy, _| {
            observations.set(observations.get() + 1);
            Ok(current(&native, owner, policy))
        })
        .unwrap();
    assert!(admission.is_some());
    assert!(
        journal::publish_intent(&directory, &original)
            .unwrap()
            .is_none(),
        "existing equal bytes mint no receipt"
    );
    drop(ports);
    let mut unavailable = UnavailablePeers::start(&prepared);
    let account = grant
        .bind_account(AccountService::new(owner.authority.config.clone()).unwrap())
        .unwrap();
    attempts::generated(
        &directory,
        Purpose::ReservePolicy,
        original.digest().unwrap(),
        &attempts::HistoryScope::FixedBody,
        &grant,
        deadline,
        None,
        |attempt| {
            account
                .inspect_initial_reserve_policy_preparation_in_parent(
                    attempt.directory(),
                    std::ffi::OsStr::new("transaction"),
                    &original.request(attempt.terms(), deadline),
                )
                .map_err(|_| invalid("native initial inspection failed"))
        },
        |_| Err(invalid("no initial predecessor may retire")),
        |attempt, _, deadline| {
            account
                .retain_initial_reserve_policy_request(
                    &original.request(attempt.terms(), deadline),
                    &attempt.wallet_path(),
                )
                .map_err(|_| invalid("native initial request retention failed"))
        },
        |prerequisite, deadline| {
            owner.initial_prerequisite(&original, &mut admission, prerequisite, deadline)
        },
        |_| Ok(true),
    )
    .unwrap();
    assert_eq!(observations.get(), 1);
    assert!(admission.is_none());
    assert!(
        unavailable.requests.lock().unwrap().is_empty(),
        "unsigned retention reacquired no source"
    );
    let selected = journal::required_original(&directory).unwrap();
    let request = selected.request(deadline);
    let wallet = selected.directory().path().join("transaction");
    assert_eq!(
        account
            .inspect_initial_reserve_policy_preparation(&wallet, &request)
            .unwrap()
            .phase(),
        iroha_wallet::operations::NativePreparationPhase::RequestOnly
    );
    let request_bytes = std::fs::read(wallet.join("preparation.json")).unwrap();
    drop(selected);
    // A separate genuine native transaction changes the singleton before the real advance.
    let change = quote_instructions(
        &native,
        &owner.authority.config,
        [InstructionBox::from(SetSorafsReservePolicy {
            policy: policy.clone(),
        })],
    );
    assert_eq!(native.chain.commit(vec![change]), vec![true]);
    let error = owner
        .advance_original_with_preflight(
            deadline,
            Advance::SubmitAuthorized(&grant),
            false,
            Some(account),
            |owner, policy, _| {
                observations.set(observations.get() + 1);
                let (cut, proof) = current(&native, owner, policy);
                assert!(proof.current().is_some());
                (Some(cut), Some(proof))
            },
        )
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("fresh reserve singleton absence unavailable"),
        "{error}"
    );
    assert_eq!(observations.get(), 2);
    assert_eq!(
        std::fs::read(wallet.join("preparation.json")).unwrap(),
        request_bytes
    );
    for file in ["payload.json", "operation.json", "submission.json"] {
        assert!(!wallet.join(file).exists());
    }
    assert!(
        unavailable.requests.lock().unwrap().is_empty(),
        "refusal preceded quote/funding/sign/dispatch"
    );
    // Ordinary reopening cannot recreate the publication receipt or silently recover freshness.
    let (_, recovered) = owner
        .select_intent_using(&directory, &policy, deadline, |_, _, _| {
            Err(invalid("retained intent must not invoke selection source"))
        })
        .unwrap();
    assert!(recovered.is_none());
    unavailable.finish();
}

#[test]
fn equal_original_and_late_active_proof_admissions_use_the_canonical_source() {
    let _resources = crate::managed::native_test_guard();
    for late_active in [false, true] {
        let temporary = tempfile::tempdir().unwrap();
        let ports = crate::managed::LocalnetPorts::reserve().unwrap();
        let prepared = crate::localnet::prepare_localnet_at(
            "initial-proof-fallback",
            &temporary.path().join("generation"),
            &ports,
            crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities,
            None,
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(600);
        let mut parent = ManagedServiceBootstrap::open(&prepared).unwrap();
        let authorization = parent
            .authorize_generated_startup(deadline, Arc::new(AtomicBool::new(false)))
            .unwrap()
            .unwrap();
        let grant = authorization.test_child(Purpose::ReservePolicy).unwrap();
        let mut owner = ManagedInitialReservePolicy::open(&prepared).unwrap();
        let policy = grant.policies().network.reserve.clone();
        let mut native = NativeFixture::from_generated(&prepared, &owner.authority);
        let log = quote_instructions(
            &native,
            &owner.authority.config,
            [InstructionBox::from(Log::new(
                iroha_data_model::Level::INFO,
                "fallback original".into(),
            ))],
        );
        assert_eq!(native.chain.commit(vec![log]), vec![true]);
        let directory = owner.authority.directory.ensure_child("set").unwrap();
        let (original, mut admission) = owner
            .select_intent_using(&directory, &policy, deadline, |owner, policy, _| {
                Ok(current(&native, owner, policy))
            })
            .unwrap();
        assert!(admission.is_some());
        if !late_active {
            // Existing equal Original cannot recreate the consumed CreateNew owner.
            drop(admission.take());
            let (same, recovered) = owner
                .select_intent_using(&directory, &policy, deadline, |_, _, _| {
                    Err(invalid("retained Original cannot be reselected"))
                })
                .unwrap();
            assert_eq!(same.digest().unwrap(), original.digest().unwrap());
            assert!(recovered.is_none());
            admission = recovered;
        }
        drop(ports);
        let mut unavailable = UnavailablePeers::start(&prepared);
        let entered = Cell::new(false);
        let wide = norito::DecodeLimits::new(
            super::super::native_operation::MAX_CHECKPOINT_BYTES,
            super::super::native_operation::MAX_CHECKPOINT_BYTES,
            super::super::native_operation::MAX_CHECKPOINT_BYTES,
            64 * 1024 * 1024,
            64,
        );
        let budget = norito::core::DecodeBudgetContext::new(wide);
        let error = attempts::generated(
            &directory,
            Purpose::ReservePolicy,
            original.digest().unwrap(),
            &attempts::HistoryScope::FixedBody,
            &grant,
            deadline,
            None,
            |_| Err(invalid("first missing wallet needs no inspection")),
            |_| Err(invalid("first reservation has no predecessor")),
            |_, _, _| {
                Err(invalid(
                    "failed canonical prerequisite cannot retain a wallet",
                ))
            },
            |prerequisite, deadline| {
                entered.set(true);
                if late_active {
                    budget.with(|| {
                        owner.initial_prerequisite(
                            &original,
                            &mut admission,
                            prerequisite,
                            deadline,
                        )
                    })
                } else {
                    owner.initial_prerequisite(&original, &mut admission, prerequisite, deadline)
                }
            },
            |_| Ok(true),
        )
        .unwrap_err();
        assert!(entered.get());
        assert!(
            !error.to_string().contains("cannot retain a wallet"),
            "{error}"
        );
        assert!(
            !unavailable.requests.lock().unwrap().is_empty(),
            "fallback must acquire the ordinary source"
        );
        assert!(admission.is_none());
        if late_active {
            assert!(budget.consumed_allocated_bytes() > 0);
            assert!(budget.consumed_allocated_bytes() <= 64 * 1024 * 1024);
        }
        let history = attempts::History::read(
            &directory,
            Purpose::ReservePolicy,
            original.digest().unwrap(),
            &attempts::HistoryScope::FixedBody,
        )
        .unwrap();
        assert_eq!(history.reserved_attempt_count(), 1);
        let first = history.last().unwrap();
        assert!(!first.wallet_path().exists());
        assert!(!first.directory().path().join("observation.nrt").exists());
        unavailable.finish();
    }
}
