//! Genuine generated setup replay, exact carrier custody and offline recovery.
//!
//! Exact wallet envelopes are committed directly through the existing native component fixture.
//! These controls do not establish full coordinator HTTP success or daemon qualification. Native
//! identical-policy replay retains the first policy origin; the new carrier proves execution only.
//! A fresh gateway setup restores explicitly revoked grants; duplicate grants are never idempotent.

use super::tests::{fixture, options};
use super::*;
use crate::managed::native_operation::Fees;
use crate::{
    managed::native_operation::{
        test_support::{
            UnavailablePeers,
            gateway_setup_native_tests::native_configured_gateway,
            native_fixture::{NativeFixture, NativeReadHttp, balance, quote_instructions},
        },
        verify_carrier,
    },
    verify::finality::FinalityVerifier,
};
use iroha_core::{
    smartcontracts::ValidSingularQuery,
    state::{StorageReadOnly as _, WorldReadOnly},
};
use iroha_data_model::{
    asset::{AssetDefinitionId, AssetId},
    isi::Revoke,
    permission::Permission,
    query::sorafs::prelude::FindSorafsReputationJournalAuthorityPolicy,
    sorafs::reputation::ReputationJournalPolicyOriginV1,
};
use iroha_executor_data_model::permission::sorafs::{
    CanCheckSorafsStreamTokenGateway, CanOperateSorafsStreamTokenGateway,
};
use iroha_fs::PublishMode;
use iroha_primitives::numeric::Quantity;
use std::{collections::BTreeMap, sync::Arc, time::Duration};

fn original(owner: &Setup, intent: Intent, checkpoint: &FinalityVerifier) -> Original {
    let original = Original {
        intent,
        checkpoint: checkpoint_bytes(checkpoint).unwrap(),
    };
    owner.validate_original(&original).unwrap();
    original
}
fn only_original(verifier: &FinalityVerifier, signed: &SignedTransaction, height: u64) {
    let tip = verifier.verified_tip().unwrap();
    assert_eq!(tip.height(), height);
    assert_eq!(tip.block().network_entrypoint_count(), 1);
    assert_eq!(
        tip.block()
            .external_transactions()
            .next()
            .unwrap()
            .encode_wire_v1()
            .unwrap(),
        signed.encode_wire_v1().unwrap()
    );
}
fn maximum_fee(http: &NativeReadHttp, asset: &AssetDefinitionId) -> Quantity {
    let quote = http.quote.lock().unwrap().take().unwrap();
    assert!(!quote.components.is_empty());
    assert_eq!(
        http.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, path)| path == "/v1/fees/quote")
            .count(),
        1
    );
    quote
        .components
        .iter()
        .fold(Quantity::zero(), |sum, component| {
            assert_eq!(&component.asset_definition_id, asset);
            sum.checked_add(&component.max_amount).unwrap()
        })
}

#[test]
fn exact_managed_setup_replays_policy_restores_missing_grants_and_recovers_original_carriers() {
    let _guard = crate::managed::native_test_guard();
    let (_root, prepared) = fixture();
    // The sole shared fixture retains every original H2-H6 positive/rollback assertion.
    let configured = native_configured_gateway(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
    );
    let mut native = configured.native;
    let mut gateway = ManagedInitialGatewaySetup::open(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
    )
    .unwrap();
    let mut recorder = ManagedInitialReputationPolicy::open(&prepared).unwrap();
    let manager = gateway.inner.authority.config.clone();
    let asset = AssetDefinitionId::parse_address_literal(
        crate::genesis::profile::TAIRA_XOR_ASSET_DEFINITION_ID,
    )
    .unwrap();
    let manager_asset = AssetId::new(asset.clone(), manager.account.clone());
    let role_assets = [
        gateway.inner.authority.provider_role(StreamTokenAuthorityRole::GatewayOperator).unwrap(),
        gateway.inner.authority.provider_role(StreamTokenAuthorityRole::GatewayObserver).unwrap(),
        recorder.inner.authority.network_role(crate::localnet::service_authorities::NetworkServiceAuthorityRole::ReputationRecorder).unwrap(),
    ].map(|account| AssetId::new(asset.clone(), account.clone()));
    let role_before = role_assets
        .each_ref()
        .map(|asset| balance(native.chain.state(), asset));
    // Configure is an exact policy replay, but the two following Grant instructions reject
    // existing direct permissions. Create the real missing-grant state through the manager's
    // authorized native Revoke path instead of changing instruction or duplicate-grant semantics.
    let gateway_id = configured.gateway_policy.qualification.gateway_id;
    let operator = gateway
        .inner
        .authority
        .provider_role(StreamTokenAuthorityRole::GatewayOperator)
        .unwrap()
        .clone();
    let observer = gateway
        .inner
        .authority
        .provider_role(StreamTokenAuthorityRole::GatewayObserver)
        .unwrap()
        .clone();
    let operate: Permission = CanOperateSorafsStreamTokenGateway { gateway_id }.into();
    let check: Permission = CanCheckSorafsStreamTokenGateway { gateway_id }.into();
    let permissions = |native: &NativeFixture| {
        let view = native.chain.state().view();
        view.world()
            .account_permissions()
            .iter()
            .map(|(account, permissions)| (account.clone(), permissions.clone()))
            .collect::<BTreeMap<_, _>>()
    };
    let original_permissions = permissions(&native);
    let mut missing_permissions = original_permissions.clone();
    assert!(
        missing_permissions
            .get_mut(&operator)
            .unwrap()
            .remove(&operate)
    );
    assert!(
        missing_permissions
            .get_mut(&observer)
            .unwrap()
            .remove(&check)
    );
    // Preserve the complete real gateway namespace, including the immutable policy record's
    // execution origin. These opaque bytes are compared, never decoded into a fixture authority.
    let gateway_prefix = format!(
        "sorafs_stream_token_gateway_v1/{}/",
        hex::encode(gateway_id)
    );
    let gateway_rows = |native: &NativeFixture| {
        let view = native.chain.state().view();
        view.world()
            .smart_contract_state()
            .iter()
            .filter(|(path, _)| path.as_ref().starts_with(&gateway_prefix))
            .map(|(path, bytes)| (path.as_ref().to_owned(), bytes.clone()))
            .collect::<BTreeMap<_, _>>()
    };
    let original_gateway_rows = gateway_rows(&native);
    for suffix in [
        "head",
        "policy/head",
        "policy/revision/00000000000000000001",
    ] {
        assert!(original_gateway_rows.contains_key(&format!("{gateway_prefix}{suffix}")));
    }
    let original_recorder_policy = FindSorafsReputationJournalAuthorityPolicy
        .execute(&native.chain.state().view())
        .unwrap();
    let revoke = quote_instructions(
        &native,
        &manager,
        [
            Revoke::account_permission(operate, operator).into(),
            Revoke::account_permission(check, observer).into(),
        ],
    );
    revoke.verify_signature().unwrap();
    assert_eq!(revoke.authority(), &manager.account);
    let revoke_maximum = revoke.fee_payment_intent().charge_limits().iter().fold(
        Quantity::zero(),
        |sum, component| {
            assert_eq!(&component.asset_definition_id, &asset);
            sum.checked_add(&component.max_amount).unwrap()
        },
    );
    let manager_before_revoke = balance(native.chain.state(), &manager_asset);
    let revoked = native.chain.commit(vec![revoke.clone()]);
    assert_eq!(
        revoked,
        vec![true],
        "authorized exact grant revocation native result: {:?}",
        native
            .chain
            .committed(7)
            .block()
            .network_output_at(0)
            .unwrap()
            .1
            .result,
    );
    assert_eq!(permissions(&native), missing_permissions);
    assert_eq!(gateway_rows(&native), original_gateway_rows);
    assert_eq!(
        FindSorafsReputationJournalAuthorityPolicy
            .execute(&native.chain.state().view())
            .unwrap(),
        original_recorder_policy,
    );
    let revoke_fee = manager_before_revoke
        .checked_sub(&balance(native.chain.state(), &manager_asset))
        .unwrap();
    assert!(!revoke_fee.is_zero() && revoke_fee <= revoke_maximum);
    assert_eq!(
        role_assets
            .each_ref()
            .map(|asset| balance(native.chain.state(), asset)),
        role_before,
    );
    let setup_checkpoint = native.observe(&gateway.inner.authority);
    only_original(&setup_checkpoint, &revoke, 7);
    assert_eq!(
        verify_carrier(&setup_checkpoint, &revoke).unwrap().height,
        7
    );

    let mut opts = options();
    opts.deadline = Instant::now() + Duration::from_secs(600);
    opts.max_total_fees
        .insert(asset.clone(), Quantity::from(1_000u64));
    let gateway_original = original(
        &gateway.inner,
        Intent::gateway(&gateway.inner.authority, &configured.gateway_policy).unwrap(),
        &setup_checkpoint,
    );
    let recorder_original = original(
        &recorder.inner,
        Intent::reputation(
            &recorder.inner.authority,
            &super::tests::reputation_labels(&prepared),
            &configured.reputation_policy,
        )
        .unwrap(),
        &setup_checkpoint,
    );
    let gateway_dir = gateway
        .inner
        .authority
        .directory
        .ensure_child("setup")
        .unwrap();
    let recorder_dir = recorder
        .inner
        .authority
        .directory
        .ensure_child("setup")
        .unwrap();
    let gateway_utc = now_ms().unwrap() + 1_200_000;
    let gateway_original = super::tests::retain_explicit_request(
        &gateway.inner,
        &gateway_dir,
        &gateway_original,
        || gateway_utc,
        &opts,
    );
    let recorder_utc = now_ms().unwrap() + 1_200_000;
    let recorder_original = super::tests::retain_explicit_request(
        &recorder.inner,
        &recorder_dir,
        &recorder_original,
        || recorder_utc,
        &opts,
    );
    let gateway_bytes = std::fs::read(gateway_dir.path().join("original.nrt")).unwrap();
    let recorder_bytes = std::fs::read(recorder_dir.path().join("original.nrt")).unwrap();
    let before_policy = FindSorafsReputationJournalAuthorityPolicy
        .execute(&native.chain.state().view())
        .unwrap();
    let ReputationJournalPolicyOriginV1::Network(before_origin) = &before_policy.origin else {
        panic!("native Network origin")
    };
    assert_eq!(before_origin.height, 6);
    assert_eq!(
        before_origin.transaction_hash,
        *configured.reputation_signed.hash_as_entrypoint().as_ref()
    );
    let mut peers = UnavailablePeers::start(&prepared);
    let selected = gateway
        .recover_selected_if_present(
            &configured.gateway_policy,
            &Fees::from_options(&opts).unwrap(),
            opts.deadline,
        )
        .unwrap()
        .unwrap();
    assert_eq!(selected.transaction_status, OperationStatus::Absent);
    assert!(selected.finalized.is_none());
    let selected = recorder
        .recover_selected_if_present(
            &super::tests::reputation_labels(&prepared),
            &configured.reputation_policy,
            &Fees::from_options(&opts).unwrap(),
            opts.deadline,
        )
        .unwrap()
        .unwrap();
    assert_eq!(selected.transaction_status, OperationStatus::Absent);
    assert!(selected.finalized.is_none());
    for owner in [&mut gateway.inner, &mut recorder.inner] {
        let report = owner
            .advance(Instant::now() + Duration::from_secs(15), Mode::ObserveOnly)
            .unwrap();
        assert_eq!(report.transaction_status, OperationStatus::Absent);
        assert!(report.finalized.is_none());
    }
    assert!(peers.requests.lock().unwrap().is_empty());
    for owner in [&mut gateway.inner, &mut recorder.inner] {
        let error = owner
            .advance(
                Instant::now() + Duration::from_secs(15),
                Mode::SubmitOriginal,
            )
            .err()
            .unwrap();
        assert!(
            error
                .to_string()
                .contains("fresh selected service finality unavailable"),
            "{error}"
        );
    }
    assert!(
        !gateway_original
            .directory()
            .path()
            .join("transaction/payload.json")
            .exists()
    );
    assert!(
        !gateway_original
            .directory()
            .path()
            .join("transaction/operation.json")
            .exists()
    );
    assert!(
        !recorder_original
            .directory()
            .path()
            .join("transaction/payload.json")
            .exists()
    );
    assert!(
        !recorder_original
            .directory()
            .path()
            .join("transaction/operation.json")
            .exists()
    );
    peers.finish();
    assert!(
        peers
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|r| r.method == "GET")
    );
    let wallet = AccountService::new(manager.clone()).unwrap();
    let mut http = NativeReadHttp::start_config(&manager, Arc::clone(native.chain.state()));
    gateway_original
        .request(opts.deadline)
        .prepare(
            &wallet,
            &gateway_original.directory().path().join("transaction"),
        )
        .unwrap();
    let signed_gateway = gateway
        .inner
        .verify_wallet(
            gateway_original.directory(),
            &gateway_original,
            opts.deadline,
        )
        .unwrap();
    http.finish();
    let partial_path = gateway_original.directory().path().join("transaction");
    let partial_request = gateway_original.request(opts.deadline);
    crate::managed::native_operation::test_support::preparation::payload_retained(
        &prepared,
        &partial_path,
        || partial_request.inspect(&wallet, &partial_path).unwrap(),
        |advance| {
            gateway
                .inner
                .advance(
                    opts.deadline,
                    if advance {
                        Mode::SubmitOriginal
                    } else {
                        Mode::ObserveOnly
                    },
                )
                .map(|value| {
                    assert!(value.finalized.is_none());
                    value.transaction_status
                })
        },
        || {
            partial_request.prepare(&wallet, &partial_path).unwrap();
        },
    );
    let maximum = maximum_fee(&http, &asset);
    assert_ne!(
        signed_gateway.encode_wire_v1().unwrap(),
        configured.gateway_signed.encode_wire_v1().unwrap()
    );
    let gateway_wallet = std::fs::read(
        gateway_original
            .directory()
            .path()
            .join("transaction/operation.json"),
    )
    .unwrap();
    let manager_before = balance(native.chain.state(), &manager_asset);
    let gateway_execution = native.chain.commit(vec![signed_gateway.clone()]);
    assert_eq!(
        gateway_execution,
        vec![true],
        "original gateway setup replay native result: {:?}",
        native
            .chain
            .committed(8)
            .block()
            .network_output_at(0)
            .expect("the original replay has one network entrypoint")
            .1
            .result,
    );
    assert_eq!(permissions(&native), original_permissions);
    assert_eq!(gateway_rows(&native), original_gateway_rows);
    let h8 = native.observe(&gateway.inner.authority);
    only_original(&h8, &signed_gateway, 8);
    let gateway_finality = verify_carrier(&h8, &signed_gateway).unwrap();
    gateway
        .inner
        .validate_carrier(&gateway_original, &gateway_finality)
        .unwrap();
    assert!(verify_carrier(&configured.checkpoint, &signed_gateway).is_err());
    assert!(verify_carrier(&h8, &configured.gateway_signed).is_err());
    let old = verify_carrier(&configured.checkpoint, &configured.reputation_signed).unwrap();
    assert!(
        gateway
            .inner
            .validate_carrier(&gateway_original, &old)
            .is_err()
    );
    let fee = manager_before
        .checked_sub(&balance(native.chain.state(), &manager_asset))
        .unwrap();
    assert!(!fee.is_zero() && fee <= maximum);
    gateway_original
        .directory()
        .write_atomic(
            "carrier.nrt",
            &checkpoint_bytes(&h8).unwrap(),
            PublishMode::CreateNew,
        )
        .unwrap();
    let mut http = NativeReadHttp::start_config(&manager, Arc::clone(native.chain.state()));
    recorder_original
        .request(opts.deadline)
        .prepare(
            &wallet,
            &recorder_original.directory().path().join("transaction"),
        )
        .unwrap();
    let signed_recorder = recorder
        .inner
        .verify_wallet(
            recorder_original.directory(),
            &recorder_original,
            opts.deadline,
        )
        .unwrap();
    http.finish();
    let partial_path = recorder_original.directory().path().join("transaction");
    let partial_request = recorder_original.request(opts.deadline);
    crate::managed::native_operation::test_support::preparation::payload_retained(
        &prepared,
        &partial_path,
        || partial_request.inspect(&wallet, &partial_path).unwrap(),
        |advance| {
            recorder
                .inner
                .advance(
                    opts.deadline,
                    if advance {
                        Mode::SubmitOriginal
                    } else {
                        Mode::ObserveOnly
                    },
                )
                .map(|value| {
                    assert!(value.finalized.is_none());
                    value.transaction_status
                })
        },
        || {
            partial_request.prepare(&wallet, &partial_path).unwrap();
        },
    );
    let maximum = maximum_fee(&http, &asset);
    let recorder_wallet = std::fs::read(
        recorder_original
            .directory()
            .path()
            .join("transaction/operation.json"),
    )
    .unwrap();
    let manager_before = balance(native.chain.state(), &manager_asset);
    let recorder_execution = native.chain.commit(vec![signed_recorder.clone()]);
    assert_eq!(
        recorder_execution,
        vec![true],
        "original recorder setup replay native result: {:?}",
        native
            .chain
            .committed(9)
            .block()
            .network_output_at(0)
            .expect("the original replay has one network entrypoint")
            .1
            .result,
    );
    let h9 = native.observe(&recorder.inner.authority);
    only_original(&h9, &signed_recorder, 9);
    let recorder_finality = verify_carrier(&h9, &signed_recorder).unwrap();
    recorder
        .inner
        .validate_carrier(&recorder_original, &recorder_finality)
        .unwrap();
    assert!(verify_carrier(&h8, &signed_recorder).is_err());
    assert!(verify_carrier(&h9, &signed_gateway).is_err());
    let fee = manager_before
        .checked_sub(&balance(native.chain.state(), &manager_asset))
        .unwrap();
    assert!(!fee.is_zero() && fee <= maximum);
    assert_eq!(
        role_assets
            .each_ref()
            .map(|asset| balance(native.chain.state(), asset)),
        role_before
    );
    let after_policy = FindSorafsReputationJournalAuthorityPolicy
        .execute(&native.chain.state().view())
        .unwrap();
    assert_eq!(
        after_policy, before_policy,
        "successful H9 replay preserves actual H6 policy origin"
    );
    assert_eq!(permissions(&native), original_permissions);
    assert_eq!(gateway_rows(&native), original_gateway_rows);
    assert_ne!(recorder_finality.height, before_origin.height);
    recorder_original
        .directory()
        .write_atomic(
            "carrier.nrt",
            &checkpoint_bytes(&h9).unwrap(),
            PublishMode::CreateNew,
        )
        .unwrap();
    let mut changed = gateway_original.clone();
    changed.intent = recorder_original.intent.clone();
    assert!(gateway.inner.validate_original(&changed).is_err());
    assert!(
        changed
            .request(&gateway_original.terms, opts.deadline)
            .verify(
                &gateway.inner.wallet().unwrap(),
                &gateway_original.directory().path().join("transaction")
            )
            .is_err()
    );
    drop(gateway);
    drop(recorder);
    let mut peers = UnavailablePeers::start(&prepared);
    for _ in 0..2 {
        let mut gateway = ManagedInitialGatewaySetup::open(
            &prepared,
            crate::managed::native_operation::test_support::provider_id(&prepared, 0),
        )
        .unwrap();
        let mut recorder = ManagedInitialReputationPolicy::open(&prepared).unwrap();
        let selected_options = gateway_original
            .terms
            .options(Instant::now() + Duration::from_secs(15));
        let selected_utc = gateway_original.terms.requested_deadline_unix_ms;
        let selected = gateway
            .recover_selected_if_present(
                &configured.gateway_policy,
                &Fees::from_options(&selected_options).unwrap(),
                selected_options.deadline,
            )
            .unwrap()
            .unwrap();
        assert_eq!(selected.transaction_status, OperationStatus::Applied);
        assert_eq!(selected.finalized, Some(gateway_finality));
        let mut changed = configured.gateway_policy.clone();
        changed.qualification.max_pending += 1;
        changed.qualification.policy_digest = changed.calculate_policy_digest().unwrap();
        assert!(
            gateway
                .recover_selected_if_present(
                    &changed,
                    &Fees::from_options(&selected_options).unwrap(),
                    selected_options.deadline
                )
                .is_err()
        );
        assert!(
            gateway_original
                .matches(
                    &gateway_original.intent,
                    selected_utc + 1,
                    &selected_options
                )
                .is_err()
        );
        let mut changed_options = gateway_original.terms.options(selected_options.deadline);
        changed_options.max_total_fees.clear();
        assert!(
            gateway
                .recover_selected_if_present(
                    &configured.gateway_policy,
                    &Fees::from_options(&changed_options).unwrap(),
                    changed_options.deadline
                )
                .is_err()
        );
        let label = &super::tests::reputation_labels(&prepared);
        let selected_utc = recorder_original.terms.requested_deadline_unix_ms;
        let selected = recorder
            .recover_selected_if_present(
                label,
                &configured.reputation_policy,
                &Fees::from_options(&selected_options).unwrap(),
                selected_options.deadline,
            )
            .unwrap()
            .unwrap();
        assert_eq!(selected.transaction_status, OperationStatus::Applied);
        assert_eq!(selected.finalized, Some(recorder_finality));
        let mut changed = configured.reputation_policy.clone();
        changed.max_source_age_ms += 1;
        assert!(
            recorder
                .recover_selected_if_present(
                    label,
                    &changed,
                    &Fees::from_options(&selected_options).unwrap(),
                    selected_options.deadline
                )
                .is_err()
        );
        let mut changed_label = label.to_vec();
        changed_label[0].push_str("-changed");
        let changed = super::tests::reputation(&recorder.inner.authority, &changed_label);
        assert!(
            recorder
                .recover_selected_if_present(
                    &changed_label,
                    &changed,
                    &Fees::from_options(&selected_options).unwrap(),
                    selected_options.deadline
                )
                .is_err()
        );
        assert!(
            recorder_original
                .matches(
                    &recorder_original.intent,
                    selected_utc + 1,
                    &selected_options
                )
                .is_err()
        );
        assert!(
            recorder
                .recover_selected_if_present(
                    label,
                    &configured.reputation_policy,
                    &Fees::from_options(&changed_options).unwrap(),
                    changed_options.deadline
                )
                .is_err()
        );
        assert!(peers.requests.lock().unwrap().is_empty());
        for result in [
            gateway
                .recover(Instant::now() + Duration::from_secs(15))
                .unwrap(),
            gateway
                .advance(Instant::now() + Duration::from_secs(15))
                .unwrap(),
        ] {
            assert_eq!(result.transaction_status, OperationStatus::Applied);
            assert_eq!(result.finalized, Some(gateway_finality));
        }
        for result in [
            recorder
                .recover(Instant::now() + Duration::from_secs(15))
                .unwrap(),
            recorder
                .advance(Instant::now() + Duration::from_secs(15))
                .unwrap(),
        ] {
            assert_eq!(result.transaction_status, OperationStatus::Applied);
            assert_eq!(result.finalized, Some(recorder_finality));
        }
        assert!(peers.requests.lock().unwrap().is_empty());
        assert_eq!(
            gateway
                .inner
                .verify_wallet(
                    gateway_original.directory(),
                    &gateway_original,
                    Instant::now() + Duration::from_secs(15)
                )
                .unwrap()
                .encode_wire_v1()
                .unwrap(),
            signed_gateway.encode_wire_v1().unwrap()
        );
        assert_eq!(
            recorder
                .inner
                .verify_wallet(
                    recorder_original.directory(),
                    &recorder_original,
                    Instant::now() + Duration::from_secs(15)
                )
                .unwrap()
                .encode_wire_v1()
                .unwrap(),
            signed_recorder.encode_wire_v1().unwrap()
        );
    }
    peers.finish();
    assert_eq!(
        std::fs::read(gateway_dir.path().join("original.nrt")).unwrap(),
        gateway_bytes
    );
    assert_eq!(
        std::fs::read(recorder_dir.path().join("original.nrt")).unwrap(),
        recorder_bytes
    );
    assert_eq!(
        std::fs::read(
            gateway_original
                .directory()
                .path()
                .join("transaction/operation.json")
        )
        .unwrap(),
        gateway_wallet
    );
    assert_eq!(
        std::fs::read(
            recorder_original
                .directory()
                .path()
                .join("transaction/operation.json")
        )
        .unwrap(),
        recorder_wallet
    );
    assert!(
        !gateway_original
            .directory()
            .path()
            .join("transaction/submission.json")
            .exists()
    );
    assert!(
        !recorder_original
            .directory()
            .path()
            .join("transaction/submission.json")
            .exists()
    );
}

#[test]
fn genuine_unprepared_service_intents_expire_without_http_or_wallet_even_after_reopen() {
    let _guard = crate::managed::native_test_guard();
    let (_root, prepared) = fixture();
    let configured = native_configured_gateway(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
    );
    let gateway = ManagedInitialGatewaySetup::open(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
    )
    .unwrap();
    let recorder = ManagedInitialReputationPolicy::open(&prepared).unwrap();
    let opts = options();
    let checkpoint = checkpoint_bytes(&configured.checkpoint).unwrap();
    let gateway_intent =
        Intent::gateway(&gateway.inner.authority, &configured.gateway_policy).unwrap();
    let recorder_intent = Intent::reputation(
        &recorder.inner.authority,
        &super::tests::reputation_labels(&prepared),
        &configured.reputation_policy,
    )
    .unwrap();
    let gateway_original = Original {
        intent: gateway_intent,
        checkpoint: checkpoint.clone(),
    };
    let recorder_original = Original {
        intent: recorder_intent,
        checkpoint,
    };
    let gateway_dir = gateway
        .inner
        .authority
        .directory
        .ensure_child("setup")
        .unwrap();
    let recorder_dir = recorder
        .inner
        .authority
        .directory
        .ensure_child("setup")
        .unwrap();
    gateway.inner.validate_original(&gateway_original).unwrap();
    recorder
        .inner
        .validate_original(&recorder_original)
        .unwrap();
    // Give each independent original the same 500 ms interval only after its native proof
    // and helper prelude are complete; the first journal must not spend the second's window.
    let gateway_original = super::tests::retain_explicit_request(
        &gateway.inner,
        &gateway_dir,
        &gateway_original,
        || now_ms().unwrap() + 500,
        &opts,
    );
    let recorder_original = super::tests::retain_explicit_request(
        &recorder.inner,
        &recorder_dir,
        &recorder_original,
        || now_ms().unwrap() + 500,
        &opts,
    );
    let gateway_bytes = std::fs::read(gateway_dir.path().join("original.nrt")).unwrap();
    let recorder_bytes = std::fs::read(recorder_dir.path().join("original.nrt")).unwrap();
    let prefix_names = [
        "authorization.nrt",
        "observation.nrt",
        "committed.nrt",
        "transaction/preparation.json",
    ];
    let prefixes = [&gateway_original, &recorder_original].map(|selected| {
        prefix_names.map(|name| std::fs::read(selected.directory().path().join(name)).unwrap())
    });
    let utc = gateway_original
        .terms
        .requested_deadline_unix_ms
        .max(recorder_original.terms.requested_deadline_unix_ms);
    let limit = Instant::now() + Duration::from_secs(2);
    while now_ms().unwrap() < utc {
        assert!(Instant::now() < limit);
        std::thread::sleep(Duration::from_millis(5));
    }
    drop(gateway);
    drop(recorder);
    let mut peers = UnavailablePeers::start(&prepared);
    let mut gateway = ManagedInitialGatewaySetup::open(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
    )
    .unwrap();
    let mut recorder = ManagedInitialReputationPolicy::open(&prepared).unwrap();
    for result in [
        gateway
            .recover(Instant::now() + Duration::from_secs(15))
            .unwrap(),
        gateway
            .advance(Instant::now() + Duration::from_secs(15))
            .unwrap(),
        recorder
            .recover(Instant::now() + Duration::from_secs(15))
            .unwrap(),
        recorder
            .advance(Instant::now() + Duration::from_secs(15))
            .unwrap(),
    ] {
        assert_eq!(result.transaction_status, OperationStatus::Expired);
        assert!(result.finalized.is_none());
    }
    for (selected, before) in [&gateway_original, &recorder_original]
        .into_iter()
        .zip(prefixes)
    {
        for (name, bytes) in prefix_names.into_iter().zip(before) {
            assert_eq!(
                std::fs::read(selected.directory().path().join(name)).unwrap(),
                bytes
            );
        }
        assert!(
            !selected
                .directory()
                .path()
                .join("transaction/submission.json")
                .exists()
        );
    }
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
    assert!(
        !gateway_original
            .directory()
            .path()
            .join("transaction/payload.json")
            .exists()
    );
    assert!(
        !gateway_original
            .directory()
            .path()
            .join("transaction/operation.json")
            .exists()
    );
    assert!(
        !recorder_original
            .directory()
            .path()
            .join("transaction/payload.json")
            .exists()
    );
    assert!(
        !recorder_original
            .directory()
            .path()
            .join("transaction/operation.json")
            .exists()
    );
    assert_eq!(
        std::fs::read(gateway_dir.path().join("original.nrt")).unwrap(),
        gateway_bytes
    );
    assert_eq!(
        std::fs::read(recorder_dir.path().join("original.nrt")).unwrap(),
        recorder_bytes
    );
}
