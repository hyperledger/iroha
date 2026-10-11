//! Actual generated Global execution and original paid wallet/carrier controls. The child
//! anchor is a private certificate fixture; this does not qualify a running private network.

use super::native_fixture::{NativeFixture, NativeReadHttp, balance, quote_instructions};
use crate::{
    localnet::{LocalnetServiceProfile, prepare_localnet_at},
    managed::{
        LocalnetPorts,
        native_operation::{
            now_ms, retain_carrier_execution_progress, retain_carrier_progress,
            retained_carrier_execution, verify_carrier,
        },
        service_authority::{NetworkPurpose, ProviderPurpose, ServiceAuthority},
    },
    verify::finality::FinalityVerifier,
};
use iroha_core::state::WorldReadOnly;
use iroha_data_model::{
    ValidationFail,
    asset::{AssetDefinitionId, AssetId},
    block::consensus::SumeragiRootScope,
    isi::{Grant, InstructionBox, Log, error::InstructionExecutionError},
    permission::Permission,
    private_dataspace::PrivateDataspaceRegistration,
    sumeragi_finality::{authenticated_genesis, test_fixtures::NativeFinalityFixture},
    transaction::{FeePaymentIntent, error::TransactionRejectionReason},
};
use iroha_executor_data_model::permission::parameter::CanSetParameters;
use iroha_fs::PrivateDirectory;
use iroha_model_base::topology::DataSpaceId;
use iroha_primitives::numeric::Quantity;
use iroha_wallet::operations::{
    AccountService, AmxDataspaceRegistrationRequest, BoundedTransactionOptions,
};
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, Instant},
};

fn request(parent: &iroha::config::Config) -> AmxDataspaceRegistrationRequest {
    let scope = SumeragiRootScope::Dataspace {
        parent_network_id: parent.network_id,
        dataspace_id: DataSpaceId::new(319),
    };
    let child = NativeFinalityFixture::start_with_scope("native-administrative-private", scope);
    let decision = child
        .verifier()
        .verify_retained_decision(child.genesis_proof())
        .unwrap();
    let registration = PrivateDataspaceRegistration::new(
        scope,
        child.chain_id().parse().unwrap(),
        child.network_id(),
        decision.result().0,
        authenticated_genesis(child.genesis())
            .map(|genesis| genesis.into_parts().0)
            .unwrap(),
    )
    .unwrap();
    AmxDataspaceRegistrationRequest {
        parent_chain_id: parent.chain.to_string(),
        registration,
        deadline_unix_ms: now_ms().unwrap() + 600_000,
        options: BoundedTransactionOptions {
            fee_payment: FeePaymentIntent::authority(Vec::new(), None),
            max_total_fees: BTreeMap::from([(
                AssetDefinitionId::parse_address_literal(
                    crate::genesis::profile::TAIRA_XOR_ASSET_DEFINITION_ID,
                )
                .unwrap(),
                Quantity::from(1_000_000_u32),
            )]),
            deadline: Instant::now() + Duration::from_secs(600),
        },
    }
}

fn fixture() -> (
    tempfile::TempDir,
    crate::managed::PreparedLocalnet,
    ServiceAuthority,
    NativeFixture,
) {
    let root = tempfile::tempdir().unwrap();
    let ports = LocalnetPorts::reserve().unwrap();
    let prepared = prepare_localnet_at(
        "native-amx-admin",
        &root.path().join("generation"),
        &ports,
        LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    drop(ports);
    let authority =
        ServiceAuthority::open_network(&prepared, NetworkPurpose::InitialReservePolicy).unwrap();
    let native = NativeFixture::from_generated(&prepared, &authority);
    (root, prepared, authority, native)
}

// The observed-carrier handoff joins two non-genesis Global receipts. Commit real paid
// work before preparing registration, matching the production handoff's eligible parent.
fn certified_parent(native: &mut NativeFixture, authority: &ServiceAuthority) -> FinalityVerifier {
    assert_eq!(native.chain.height(), 1);
    let signed = quote_instructions(
        native,
        &authority.config,
        [InstructionBox::from(Log::new(
            iroha_data_model::Level::INFO,
            "authenticate AMX registration parent".into(),
        ))],
    );
    assert_eq!(native.chain.commit(vec![signed.clone()]), vec![true]);
    let parent = native.observe(authority);
    assert_eq!(parent.checkpoint().height(), 2);
    assert_eq!(verify_carrier(&parent, &signed).unwrap().height, 2);
    parent
}

/// Lend genuine wallet-produced bytes to attachment custody controls without inventing a proof.
pub(crate) fn with_signed_amx_preparation(
    inspect: impl FnOnce(&iroha::config::Config, &AmxDataspaceRegistrationRequest, &std::path::Path),
) {
    let _resources = crate::managed::native_test_guard();
    let (root, _prepared, authority, native) = fixture();
    let request = request(&authority.config);
    let journal = root.path().join("original-admin-prefix");
    let wallet = AccountService::new(authority.config.clone()).unwrap();
    let mut http =
        NativeReadHttp::start_config(&authority.config, Arc::clone(native.chain.state()));
    wallet
        .prepare_amx_dataspace_registration(&request, &journal)
        .unwrap();
    wallet
        .verify_amx_dataspace_registration_journal(&journal, &request)
        .unwrap()
        .verify_signature()
        .unwrap();
    http.finish();
    inspect(&authority.config, &request, &journal);
}

#[test]
fn administrative_amx_native_paid_original_wire_is_registered_and_carrier_reopens_without_replacement()
 {
    let _resources = crate::managed::native_test_guard();
    let (root, _prepared, authority, mut native) = fixture();
    let original = certified_parent(&mut native, &authority);
    let request = request(&authority.config);
    let payer = AssetId::new(
        request
            .options
            .max_total_fees
            .keys()
            .next()
            .unwrap()
            .clone(),
        authority.config.account.clone(),
    );
    let before = balance(native.chain.state(), &payer);
    let journal = root.path().join("original-admin");
    let wallet = AccountService::new(authority.config.clone()).unwrap();
    let mut http =
        NativeReadHttp::start_config(&authority.config, Arc::clone(native.chain.state()));
    wallet
        .prepare_amx_dataspace_registration(&request, &journal)
        .unwrap();
    let signed = wallet
        .verify_amx_dataspace_registration_journal(&journal, &request)
        .unwrap();
    signed.verify_signature().unwrap();
    let wire = signed.encode_wire_v1().unwrap();
    http.finish();
    // Applied/Rejected node hints cannot make an original transaction appear in a carrier.
    assert!(verify_carrier(&original, &signed).is_err());
    assert!(super::super::verify_carrier_execution(&original, &signed, false).is_err());
    assert_eq!(native.chain.commit(vec![signed.clone()]), vec![true]);
    assert!(
        balance(native.chain.state(), &payer) < before,
        "original registration pays its actual native fee"
    );
    let view = native.chain.state().view();
    let tracker = view
        .world()
        .sumeragi_amx()
        .dataspace(request.registration.scope.dataspace_id())
        .unwrap();
    assert_eq!(tracker.tracker.instance, request.registration.instance);
    drop(view);
    let observed = native.observe(&authority);
    assert_eq!(observed.checkpoint().height(), 3);
    observed
        .verified_tip_ref()
        .unwrap()
        .verify_immediate_global_successor_of(
            original.verified_tip_ref().unwrap(),
            original.checkpoint().network_id(),
            original.checkpoint().chain_id(),
        )
        .unwrap();
    let expected = verify_carrier(&observed, &signed).unwrap();
    let immediate = PrivateDirectory::open_or_create(root.path().join("observed-receipt")).unwrap();
    let mut observed_start = original.clone();
    assert_eq!(
        super::super::retain_observed_carrier(
            &immediate,
            &signed,
            &mut observed_start,
            &observed,
            request.options.deadline,
        )
        .unwrap(),
        Some(expected)
    );
    assert_eq!(
        immediate
            .read("carrier.nrt", super::super::MAX_CHECKPOINT_BYTES)
            .unwrap()
            .as_slice(),
        super::super::checkpoint_bytes(&observed)
            .unwrap()
            .as_slice()
    );
    let receipt = PrivateDirectory::open_or_create(root.path().join("native-receipt")).unwrap();
    let mut replay = original;
    let admitted = retain_carrier_execution_progress(
        &receipt,
        &signed,
        &mut replay,
        expected.height,
        &native,
        false,
    )
    .unwrap()
    .unwrap();
    assert!(admitted.applied);
    assert_eq!(admitted.finality, expected);
    assert_eq!(
        crate::attachment::AmxRegistrationFinality::from(admitted),
        crate::attachment::AmxRegistrationFinality::Registered(expected)
    );
    let bytes = receipt
        .read("carrier.nrt", super::super::MAX_CHECKPOINT_BYTES)
        .unwrap();
    drop(receipt);
    let reopened = PrivateDirectory::open(root.path().join("native-receipt")).unwrap();
    assert_eq!(
        retained_carrier_execution(
            &reopened,
            authority.config.network_id,
            &authority.config.chain.to_string(),
            &signed
        )
        .unwrap(),
        Some(admitted)
    );
    assert_eq!(
        reopened
            .read("carrier.nrt", super::super::MAX_CHECKPOINT_BYTES)
            .unwrap()
            .as_slice(),
        bytes.as_slice()
    );
    assert_eq!(
        wallet
            .verify_amx_dataspace_registration_journal(&journal, &request)
            .unwrap()
            .encode_wire_v1()
            .unwrap(),
        wire
    );
}

#[test]
fn administrative_amx_native_missing_permission_is_authenticated_failure_after_later_grant() {
    let _resources = crate::managed::native_test_guard();
    let (root, prepared, authority, mut native) = fixture();
    let before_commit = certified_parent(&mut native, &authority);
    let owner = ServiceAuthority::open_provider(
        &prepared,
        super::provider_id(&prepared, 0),
        ProviderPurpose::InitialProviderCredit,
    )
    .unwrap();
    let selected = owner.issuer_operator_config().unwrap();
    assert_ne!(selected.account, authority.config.account);
    let request = request(&selected);
    let wallet = AccountService::new(selected.clone()).unwrap();
    let journal = root.path().join("failed-admin");
    let mut http = NativeReadHttp::start_config(&selected, Arc::clone(native.chain.state()));
    wallet
        .prepare_amx_dataspace_registration(&request, &journal)
        .unwrap();
    let signed = wallet
        .verify_amx_dataspace_registration_journal(&journal, &request)
        .unwrap();
    let wire = signed.encode_wire_v1().unwrap();
    http.finish();
    assert_eq!(native.chain.commit(vec![signed.clone()]), vec![false]);
    let failed = native.observe(&authority);
    assert_eq!(failed.checkpoint().height(), 3);
    failed
        .verified_tip_ref()
        .unwrap()
        .verify_immediate_global_successor_of(
            before_commit.verified_tip_ref().unwrap(),
            before_commit.checkpoint().network_id(),
            before_commit.checkpoint().chain_id(),
        )
        .unwrap();
    assert!(verify_carrier(&failed, &signed).is_err());
    let tip = failed.verified_tip().unwrap();
    let error = tip
        .block()
        .network_output_at(0)
        .unwrap()
        .1
        .result
        .as_ref()
        .unwrap_err();
    assert_eq!(
        error,
        &TransactionRejectionReason::Validation(ValidationFail::InstructionFailed(
            InstructionExecutionError::InvariantViolation(
                "AMX: AMX state rejects the transition: registering an AMX dataspace needs genesis or CanSetParameters".into(),
            ),
        )),
    );
    assert!(
        native
            .chain
            .state()
            .view()
            .world()
            .sumeragi_amx()
            .dataspace(request.registration.scope.dataspace_id())
            .is_none()
    );
    // Ordinary provisioning still requires Applied; an authenticated rejected carrier
    // must not publish successful finality. Administrative history explicitly retains it.
    let immediate =
        PrivateDirectory::open_or_create(root.path().join("rejected-observed-receipt")).unwrap();
    let mut observed_start = before_commit.clone();
    let observed_rejection = super::super::retain_observed_carrier(
        &immediate,
        &signed,
        &mut observed_start,
        &failed,
        request.options.deadline,
    );
    assert!(observed_rejection.is_err());
    assert!(
        matches!(observed_rejection, Err(crate::managed::Error::Invalid(message))
        if message == "native operation carrier lacks exact successful original execution")
    );
    assert!(
        immediate
            .read_optional("carrier.nrt", super::super::MAX_CHECKPOINT_BYTES)
            .unwrap()
            .is_none()
    );
    let strict = PrivateDirectory::open_or_create(root.path().join("strict-receipt")).unwrap();
    let mut strict_replay = before_commit.clone();
    assert!(
        retain_carrier_progress(
            &strict,
            &signed,
            &mut strict_replay,
            failed.checkpoint().height(),
            &native,
        )
        .is_err()
    );
    assert!(
        strict
            .read_optional("carrier.nrt", super::super::MAX_CHECKPOINT_BYTES)
            .unwrap()
            .is_none()
    );
    let receipt = PrivateDirectory::open_or_create(root.path().join("failed-receipt")).unwrap();
    let mut replay = before_commit;
    let retained = retain_carrier_execution_progress(
        &receipt,
        &signed,
        &mut replay,
        failed.checkpoint().height(),
        &native,
        false,
    )
    .unwrap()
    .unwrap();
    assert!(!retained.applied);
    assert_eq!(retained.finality.height, failed.checkpoint().height());
    assert_eq!(
        receipt
            .read("carrier.nrt", super::super::MAX_CHECKPOINT_BYTES)
            .unwrap()
            .as_slice(),
        super::super::checkpoint_bytes(&failed).unwrap().as_slice(),
        "retention publishes the independently verified rejected checkpoint"
    );
    let original = retained_carrier_execution(
        &receipt,
        selected.network_id,
        &selected.chain.to_string(),
        &signed,
    )
    .unwrap()
    .unwrap();
    assert_eq!(original, retained);
    assert!(!original.applied);
    assert_eq!(original.finality.transaction_hash, signed.hash());
    assert_eq!(
        crate::attachment::AmxRegistrationFinality::from(original),
        crate::attachment::AmxRegistrationFinality::Rejected(original.finality)
    );
    let grant = quote_instructions(
        &native,
        &authority.config,
        [InstructionBox::from(Grant::account_permission(
            Permission::from(CanSetParameters),
            selected.account.clone(),
        ))],
    );
    assert_eq!(native.chain.commit(vec![grant.clone()]), vec![true]);
    assert!(
        native
            .chain
            .state()
            .view()
            .world()
            .account_contains_inherent_permission(
                &selected.account,
                &Permission::from(CanSetParameters)
            )
    );
    let bytes = receipt
        .read("carrier.nrt", super::super::MAX_CHECKPOINT_BYTES)
        .unwrap();
    wallet
        .prepare_amx_dataspace_registration(&request, &journal)
        .unwrap();
    assert_eq!(
        wallet
            .verify_amx_dataspace_registration_journal(&journal, &request)
            .unwrap()
            .encode_wire_v1()
            .unwrap(),
        wire
    );
    assert_eq!(
        retained_carrier_execution(
            &receipt,
            selected.network_id,
            &selected.chain.to_string(),
            &signed
        )
        .unwrap(),
        Some(original)
    );
    assert_eq!(
        receipt
            .read("carrier.nrt", super::super::MAX_CHECKPOINT_BYTES)
            .unwrap()
            .as_slice(),
        bytes.as_slice()
    );
    assert!(
        retained_carrier_execution(
            &receipt,
            selected.network_id,
            &selected.chain.to_string(),
            &grant
        )
        .is_err()
    );
}
