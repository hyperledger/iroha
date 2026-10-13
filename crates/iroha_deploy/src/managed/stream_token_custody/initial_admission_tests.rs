//! Actual Configure native evidence cannot become a later signing prerequisite.
use super::*;
use crate::managed::native_operation::attempts::metadata;
use crate::managed::{
    native_operation::test_support::{
        UnavailablePeers,
        native_fixture::{NativeFixture, quote_instructions},
    },
    service_bootstrap::ManagedServiceBootstrap,
};
use iroha_data_model::{
    isi::{
        InstructionBox, Log,
        sorafs::{MutateSorafsStreamTokenCustody, SetSorafsReservePolicy},
    },
    sorafs::stream_token_custody::SorafsStreamTokenCustodyActionV1,
};
use std::{
    cell::Cell,
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

#[test]
fn first_configure_proof_is_consumed_before_changed_native_preparation_refusal() {
    let _resources = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet_at(
        "initial-proof-configure",
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
    let provider = crate::managed::native_operation::test_support::provider_id(&prepared, 0);
    let grant = authorization
        .test_child(Purpose::CustodyConfigure(provider))
        .unwrap();
    let mut owner = ManagedStreamTokenCustody::open(&prepared, provider).unwrap();
    let policy = grant.policies().provider(provider).unwrap().custody.clone();
    let mut native = NativeFixture::from_generated(&prepared, &owner.authority);
    let log = quote_instructions(
        &native,
        &owner.authority.config,
        [InstructionBox::from(Log::new(
            iroha_data_model::Level::INFO,
            "first Configure proof".into(),
        ))],
    );
    assert_eq!(native.chain.commit(vec![log]), vec![true]);
    // Match the stock global sequence: readiness H2, then the genuine reserve policy at H3.
    let reserve = quote_instructions(
        &native,
        &owner.authority.config,
        [InstructionBox::from(SetSorafsReservePolicy {
            policy: grant.policies().network.reserve.clone(),
        })],
    );
    assert_eq!(native.chain.commit(vec![reserve]), vec![true]);
    assert_eq!(native.chain.height(), 3);
    let directory = metadata::ensure_operation(&owner.authority.directory, "configure").unwrap();
    let observations = Cell::new(0);
    let (original, admission) = owner
        .select_configuration_using(&directory, &policy, deadline, |owner, binding, _| {
            assert_eq!(binding, &policy.binding);
            observations.set(observations.get() + 1);
            let cut = native.observe(&owner.authority);
            let proof = native.bootstrap_custody(&owner.authority, &policy, &cut);
            assert!(proof.current().is_none());
            Ok((cut, proof))
        })
        .unwrap();
    assert!(admission.is_some());
    assert!(
        journal::publish_intent(&directory, &original)
            .unwrap()
            .is_none()
    );
    drop(ports);
    let mut unavailable = UnavailablePeers::start(&prepared);
    owner
        .select_generated_attempt(
            &directory,
            &original,
            &HistoryScope::FixedBody,
            &grant,
            deadline,
            admission,
        )
        .unwrap();
    assert_eq!(observations.get(), 1);
    assert!(unavailable.requests.lock().unwrap().is_empty());
    let selected = journal::required_original(&directory).unwrap();
    let wallet = selected.directory().path().join("transaction");
    let account = grant.bind_account(owner.wallet().unwrap()).unwrap();
    assert_eq!(
        selected
            .request(deadline)
            .unwrap()
            .inspect_in_parent(&account, selected.directory())
            .unwrap()
            .phase(),
        iroha_wallet::operations::NativePreparationPhase::RequestOnly
    );
    let request_bytes = std::fs::read(wallet.join("preparation.json")).unwrap();
    // Independently author and execute the real CAS mutation; the retained request stays unsigned.
    let change = quote_instructions(
        &native,
        &owner.authority.config,
        [InstructionBox::from(MutateSorafsStreamTokenCustody {
            provider_id: provider,
            expected_revision: 0,
            expected_digest: [0; 32],
            action: SorafsStreamTokenCustodyActionV1::Configure(
                norito::encode_canonical(&policy).unwrap(),
            ),
        })],
    );
    assert_eq!(native.chain.commit(vec![change]), vec![true]);
    let error = owner
        .advance_selected_with_preflight(
            SelectedCustodyOperation {
                purpose: CustodyPurpose::Configure,
                original: selected,
            },
            deadline,
            Mode::SubmitAuthorized(&grant),
            false,
            None,
            |owner, binding, _| {
                assert_eq!(binding, &policy.binding);
                observations.set(observations.get() + 1);
                let cut = native.observe(&owner.authority);
                let proof = native.bootstrap_custody(&owner.authority, &policy, &cut);
                assert!(proof.current().is_some());
                Ok((cut, Some(proof)))
            },
        )
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("fresh custody predecessor differs"),
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
    assert!(unavailable.requests.lock().unwrap().is_empty());
    let (_, recovered) = owner
        .select_configuration_using(&directory, &policy, deadline, |_, _, _| {
            Err(invalid("retained Configure cannot reselect native state"))
        })
        .unwrap();
    assert!(recovered.is_none());
    unavailable.finish();
}
