//! Actual generated genesis, native gateway setup rollback and original wallet policy carriers.
//! This component executes exact signed envelopes directly. It establishes no daemon startup,
//! live Qualification/Pending/Serving capability, Queue, or full managed HTTP qualification.

use super::native_fixture::{NativeFixture, NativeReadHttp, balance, quote_instructions};
use crate::{
    localnet::service_authorities::StreamTokenAuthorityRole,
    managed::{
        native_operation::{now_ms, verify_carrier},
        service_authority::{ProviderPurpose, ServiceAuthority},
    },
    verify::finality::FinalityVerifier,
};
use iroha_core::{
    query::stream_token_gateway::observation::{
        StreamTokenGatewayCheckExpectedV1, StreamTokenGatewayCheckSelectorV1,
        begin_stream_token_gateway_check_v1,
    },
    smartcontracts::ValidSingularQuery,
    state::{StorageReadOnly as _, WorldReadOnly},
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    account::AccountId,
    asset::AssetId,
    executor::ValidationFail,
    isi::{
        Grant, InstructionBox, Log, error::InstructionExecutionError,
        sorafs::MutateSorafsStreamTokenGateway,
    },
    query::{error::FindError, sorafs::prelude::FindSorafsReputationJournalAuthorityPolicy},
    sorafs::{
        reputation::{
            ReputationJournalAuthorityPolicyV1, ReputationJournalPolicyOriginV1,
            derive_stream_token_gateway_id_v1,
            stream_token_delivery::StreamTokenReputationDeliveryTemplateV1,
        },
        stream_token_gateway::{
            StreamTokenGatewayAdmissionQualificationV1,
            native::{StreamTokenGatewayActionV1, StreamTokenGatewayPolicyV1},
        },
    },
    transaction::{
        Executable, FeePaymentIntent, SignedTransaction, error::TransactionRejectionReason,
    },
};
use iroha_executor_data_model::permission::sorafs::{
    CanCheckSorafsStreamTokenGateway, CanOperateSorafsStreamTokenGateway,
};
use iroha_primitives::numeric::Quantity;
use iroha_wallet::operations::{
    AccountService, BoundedTransactionOptions, InitialGatewaySetupRequest,
    InitialGatewaySetupSelection, InitialReputationPolicyRequest, InitialReputationPolicySelection,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::{Duration, Instant},
};

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

fn maximum_fee(
    http: &NativeReadHttp,
    asset: &iroha_data_model::asset::AssetDefinitionId,
) -> Quantity {
    let quote = http.quote.lock().unwrap().take().unwrap();
    assert!(!quote.components.is_empty());
    let calls = http.requests.lock().unwrap();
    assert_eq!(
        calls
            .iter()
            .filter(|(_, path)| path == "/v1/fees/quote")
            .count(),
        1
    );
    assert!(calls.iter().any(|(_, path)| path == "/v1/query"));
    quote
        .components
        .iter()
        .fold(Quantity::zero(), |sum, component| {
            assert_eq!(&component.asset_definition_id, asset);
            sum.checked_add(&component.max_amount).unwrap()
        })
}

fn has_grants(native: &NativeFixture, request: &InitialGatewaySetupRequest) -> (bool, bool) {
    let view = native.chain.state().view();
    let world = view.world();
    (
        world.account_contains_inherent_permission(
            &request.selection.operator,
            &CanOperateSorafsStreamTokenGateway {
                gateway_id: request.selection.gateway_id,
            }
            .into(),
        ),
        world.account_contains_inherent_permission(
            &request.selection.observer,
            &CanCheckSorafsStreamTokenGateway {
                gateway_id: request.selection.gateway_id,
            }
            .into(),
        ),
    )
}

#[test]
fn generated_wallet_gateway_order_rolls_back_and_recorder_set_keeps_exact_native_origin() {
    let _guard = crate::managed::native_test_guard();
    let root = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet(
        "native-gateway-wallet",
        &root.path().join("generation"),
        &ports,
    )
    .unwrap();
    drop(ports);
    let _configured = native_configured_gateway(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
    );
}

/// Genuine generated H2–H6 fixture. Every original assertion remains in this shared owner.
pub(in crate::managed) struct NativeConfiguredGateway {
    pub(in crate::managed) native: NativeFixture,
    pub(in crate::managed) gateway_policy: StreamTokenGatewayPolicyV1,
    pub(in crate::managed) reputation_policy: ReputationJournalAuthorityPolicyV1,
    pub(in crate::managed) gateway_signed: SignedTransaction,
    pub(in crate::managed) reputation_signed: SignedTransaction,
    pub(in crate::managed) checkpoint: FinalityVerifier,
}

pub(in crate::managed) fn native_configured_gateway(
    prepared: &crate::managed::PreparedLocalnet,
    provider: iroha_data_model::sorafs::capacity::ProviderId,
) -> NativeConfiguredGateway {
    // Reuse the existing test-only source/profile custody owner; no managed setup capability is
    // minted from this test lock or from the public transaction reports.
    let authority =
        ServiceAuthority::open_provider(prepared, provider, ProviderPurpose::InitialGatewaySetup)
            .unwrap();
    let manager = authority.config.clone();
    let mut native = NativeFixture::from_generated(prepared, &authority);
    let log = quote_instructions(
        &native,
        &manager,
        [InstructionBox::from(Log::new(
            iroha_data_model::Level::INFO,
            "gateway prerequisites".into(),
        ))],
    );
    assert_eq!(native.chain.commit(vec![log.clone()]), vec![true]);
    let h2 = native.observe(&authority);
    only_original(&h2, &log, 2);
    let asset = iroha_data_model::asset::AssetDefinitionId::parse_address_literal(
        crate::genesis::profile::TAIRA_XOR_ASSET_DEFINITION_ID,
    )
    .unwrap();
    let options = BoundedTransactionOptions {
        fee_payment: FeePaymentIntent::authority(Vec::new(), None),
        max_total_fees: BTreeMap::from([(asset.clone(), Quantity::from(1_000u64))]),
        deadline: Instant::now() + Duration::from_secs(600),
    };
    let label = "generated-native-wallet".to_owned();
    let gateway_id = derive_stream_token_gateway_id_v1(&manager.network_id, &label).unwrap();
    let operator = authority
        .provider_role(StreamTokenAuthorityRole::GatewayOperator)
        .unwrap()
        .clone();
    let observer = authority
        .provider_role(StreamTokenAuthorityRole::GatewayObserver)
        .unwrap()
        .clone();
    let recorder = authority
        .network_role(
            crate::localnet::service_authorities::NetworkServiceAuthorityRole::ReputationRecorder,
        )
        .unwrap()
        .clone();
    let start = h2.verified_tip().unwrap().header().creation_time_ms;
    let mut policy = StreamTokenGatewayPolicyV1 {
        network_id: manager.network_id,
        compliance_gateway_id: label.clone(),
        qualification: StreamTokenGatewayAdmissionQualificationV1 {
            gateway_id,
            revision: 1,
            policy_digest: [0; 32],
            max_pending: 64,
            max_tracked_tokens: 128,
            lease_ttl_ms: 30_000,
        },
        operators: BTreeSet::from([operator.clone()]),
        observers: BTreeSet::from([observer.clone()]),
        valid_from_unix_ms: start,
        valid_until_unix_ms: start + 1_200_000,
        max_observation_age_ms: 30_000,
        admission_enabled: true,
    };
    policy.qualification.policy_digest = policy.calculate_policy_digest().unwrap();
    let request = InitialGatewaySetupRequest {
        selection: InitialGatewaySetupSelection {
            chain_id: manager.chain.to_string(),
            network_id: manager.network_id,
            manager: manager.account.clone(),
            compliance_gateway_id: label.clone(),
            gateway_id,
            policy_digest: policy.qualification.policy_digest,
            operator: operator.clone(),
            observer: observer.clone(),
        },
        policy: policy.clone(),
        deadline_unix_ms: now_ms().unwrap() + 1_200_000,
        options: options.clone(),
    };
    assert_eq!(has_grants(&native, &request), (false, false));
    let directory = authority
        .directory
        .ensure_child("native-gateway-setup")
        .unwrap();
    let path = directory.path().join("transaction");
    let wallet = AccountService::new(manager.clone()).unwrap();
    let mut http = NativeReadHttp::start_config(&manager, Arc::clone(native.chain.state()));
    wallet
        .prepare_initial_gateway_setup(&request, &path)
        .unwrap();
    let calls = http.requests.lock().unwrap().len();
    let signed = wallet
        .verify_initial_gateway_setup_journal(&path, &request)
        .unwrap();
    assert_eq!(http.requests.lock().unwrap().len(), calls);
    http.finish();
    let maximum = maximum_fee(&http, &asset);
    signed.verify_signature().unwrap();
    assert_eq!(signed.authority(), &manager.account);
    let Executable::Instructions(items) = signed.instructions() else {
        panic!("exact setup instructions")
    };
    assert_eq!(items.len(), 3);
    let configure = items[0]
        .as_any()
        .downcast_ref::<MutateSorafsStreamTokenGateway>()
        .unwrap();
    assert_eq!(
        configure.request.action,
        StreamTokenGatewayActionV1::Configure(policy.clone())
    );
    let wire = signed.encode_wire_v1().unwrap();
    let journal = std::fs::read(path.join("operation.json")).unwrap();

    let before = quote_instructions(
        &native,
        &manager,
        [items[1].clone(), items[0].clone(), items[2].clone()],
    );
    assert_eq!(native.chain.commit(vec![before.clone()]), vec![false]);
    let refused = native.observe(&authority);
    only_original(&refused, &before, 3);
    assert_eq!(
        refused
            .verified_tip()
            .unwrap()
            .block()
            .network_output_at(0)
            .unwrap()
            .1
            .result
            .as_ref()
            .unwrap_err(),
        &TransactionRejectionReason::Validation(ValidationFail::NotPermitted(
            "authority cannot grant or revoke permission `CanOperateSorafsStreamTokenGateway`"
                .into()
        ))
    );
    assert!(verify_carrier(&refused, &before).is_err());
    assert_eq!(has_grants(&native, &request), (false, false));

    // Exercise actual transaction rollback after Configure and the first legitimate grant have
    // executed: the final scoped grant targets an absent canonical account.
    let missing = AccountId::new(
        KeyPair::try_from_seed(vec![0xA7; 32], Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .clone(),
    );
    assert!(
        native
            .chain
            .state()
            .view()
            .world()
            .accounts()
            .get(&missing)
            .is_none()
    );
    let rollback = quote_instructions(
        &native,
        &manager,
        [
            items[0].clone(),
            items[1].clone(),
            Grant::account_permission(
                CanCheckSorafsStreamTokenGateway { gateway_id },
                missing.clone(),
            )
            .into(),
        ],
    );
    assert_eq!(native.chain.commit(vec![rollback.clone()]), vec![false]);
    let refused = native.observe(&authority);
    only_original(&refused, &rollback, 4);
    assert_eq!(
        refused
            .verified_tip()
            .unwrap()
            .block()
            .network_output_at(0)
            .unwrap()
            .1
            .result
            .as_ref()
            .unwrap_err(),
        &TransactionRejectionReason::Validation(ValidationFail::InstructionFailed(
            InstructionExecutionError::Find(FindError::Account(missing))
        ))
    );
    assert!(verify_carrier(&refused, &rollback).is_err());
    assert_eq!(has_grants(&native, &request), (false, false));
    let manager_asset = AssetId::new(asset.clone(), manager.account.clone());
    let operator_asset = AssetId::new(asset.clone(), operator.clone());
    let observer_asset = AssetId::new(asset.clone(), observer.clone());
    let recorder_asset = AssetId::new(asset.clone(), recorder.clone());
    let manager_before = balance(native.chain.state(), &manager_asset);
    let other_before = [&operator_asset, &observer_asset, &recorder_asset]
        .map(|asset| balance(native.chain.state(), asset));
    assert_eq!(native.chain.commit(vec![signed.clone()]), vec![true]);
    let committed = native.observe(&authority);
    only_original(&committed, &signed, 5);
    assert_eq!(verify_carrier(&committed, &signed).unwrap().height, 5);
    assert_eq!(has_grants(&native, &request), (true, true));
    let fee = manager_before
        .checked_sub(&balance(native.chain.state(), &manager_asset))
        .unwrap();
    assert!(!fee.is_zero() && fee <= maximum);
    assert_eq!(
        [&operator_asset, &observer_asset, &recorder_asset]
            .map(|asset| balance(native.chain.state(), asset)),
        other_before
    );
    // This begins a fresh challenge against actual native current policy and permissions. It is
    // deliberately not signed/consumed here, so it is not a serving or qualification capability.
    let check = begin_stream_token_gateway_check_v1(
        Arc::clone(native.chain.state()),
        StreamTokenGatewayCheckExpectedV1 {
            network_id: manager.network_id,
            qualification: policy.qualification,
            operator: operator.clone(),
            observer: observer.clone(),
            selector: StreamTokenGatewayCheckSelectorV1::Qualification,
        },
        Instant::now() + Duration::from_secs(30),
    )
    .unwrap();
    assert_eq!(check.instruction().request.gateway_id, gateway_id);
    drop(check);
    assert_eq!(
        wallet
            .verify_initial_gateway_setup_journal(&path, &request)
            .unwrap()
            .encode_wire_v1()
            .unwrap(),
        wire
    );
    assert_eq!(std::fs::read(path.join("operation.json")).unwrap(), journal);
    assert!(!path.join("submission.json").exists());

    let gateway_signed = signed;
    let mut gateway_selection: Vec<_> = authority
        .manifest
        .providers
        .iter()
        .map(|provider| {
            let plan = prepared
                .gateway_compliance_plan(provider.provider_id)
                .unwrap()
                .unwrap();
            let label = plan.gateway_label().to_owned();
            (
                derive_stream_token_gateway_id_v1(&manager.network_id, &label).unwrap(),
                label,
            )
        })
        .collect();
    gateway_selection.sort_by_key(|(id, _)| *id);
    let gateway_ids: Vec<_> = gateway_selection.iter().map(|(id, _)| *id).collect();
    let gateway_labels: Vec<_> = gateway_selection
        .into_iter()
        .map(|(_, label)| label)
        .collect();
    let recorder_policy = ReputationJournalAuthorityPolicyV1 {
        version: 1,
        revision: 1,
        predecessor_policy_digest: None,
        por_recorder_authority: recorder.clone(),
        dispute_recorder_authority: recorder.clone(),
        token_recorder_authority: recorder.clone(),
        stream_token_delivery: StreamTokenReputationDeliveryTemplateV1 {
            allowed_gateways: gateway_ids.clone(),
            fee_payment: FeePaymentIntent::authority(Vec::new(), None),
            time_to_live_ms: 60_000,
            height_ttl: 128,
        },
        max_source_age_ms: 3_600_000,
    };
    let request = InitialReputationPolicyRequest {
        selection: InitialReputationPolicySelection {
            chain_id: manager.chain.to_string(),
            network_id: manager.network_id,
            manager: manager.account.clone(),
            compliance_gateway_ids: gateway_labels,
            gateway_ids,
            policy_digest: recorder_policy.canonical_digest().unwrap(),
            por_recorder: recorder.clone(),
            dispute_recorder: recorder.clone(),
            token_recorder: recorder.clone(),
        },
        policy: recorder_policy.clone(),
        deadline_unix_ms: now_ms().unwrap() + 1_200_000,
        options,
    };
    let directory = authority
        .directory
        .ensure_child("native-recorder-setup")
        .unwrap();
    let path = directory.path().join("transaction");
    let mut http = NativeReadHttp::start_config(&manager, Arc::clone(native.chain.state()));
    wallet
        .prepare_initial_reputation_policy(&request, &path)
        .unwrap();
    let signed = wallet
        .verify_initial_reputation_policy_journal(&path, &request)
        .unwrap();
    http.finish();
    let maximum = maximum_fee(&http, &asset);
    let manager_before = balance(native.chain.state(), &manager_asset);
    assert_eq!(native.chain.commit(vec![signed.clone()]), vec![true]);
    let committed = native.observe(&authority);
    only_original(&committed, &signed, 6);
    let carrier = verify_carrier(&committed, &signed).unwrap();
    let record = FindSorafsReputationJournalAuthorityPolicy
        .execute(&native.chain.state().view())
        .unwrap();
    assert_eq!(record.policy, recorder_policy);
    assert_eq!(record.activated_by, manager.account);
    assert_eq!(record.activated_at_unix_ms, carrier.block_time_ms);
    let ReputationJournalPolicyOriginV1::Network(execution) = record.origin else {
        panic!("exact ordinary source")
    };
    assert_eq!(execution.height, 6);
    assert_eq!(execution.entry_index, 0);
    assert_eq!(execution.instruction_index, 0);
    assert_eq!(
        execution.transaction_hash,
        *signed.hash_as_entrypoint().as_ref()
    );
    let fee = manager_before
        .checked_sub(&balance(native.chain.state(), &manager_asset))
        .unwrap();
    assert!(!fee.is_zero() && fee <= maximum);
    assert_eq!(
        [&operator_asset, &observer_asset, &recorder_asset]
            .map(|asset| balance(native.chain.state(), asset)),
        other_before
    );
    assert!(!path.join("submission.json").exists());
    assert!(verify_carrier(&h2, &signed).is_err());
    NativeConfiguredGateway {
        native,
        gateway_policy: policy,
        reputation_policy: recorder_policy,
        gateway_signed,
        reputation_signed: signed,
        checkpoint: committed,
    }
}
