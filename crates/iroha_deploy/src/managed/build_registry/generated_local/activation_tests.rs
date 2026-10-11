//! Actual retained enrollment and refusal controls; no test observation claims provider readiness.

use super::*;
use crate::managed::{
    native_operation::test_support::{
        UnavailablePeers,
        native_fixture::{NativeFixture, quote_instructions},
    },
    service_bootstrap::ManagedServiceBootstrap,
};
use iroha_data_model::{
    asset::AssetDefinitionId,
    isi::{InstructionBox, Log},
    transaction::FeePaymentIntent,
};
use iroha_primitives::numeric::Quantity;
use iroha_wallet::operations::BoundedTransactionOptions;
use std::collections::BTreeMap;

fn enrolled(
    slot: usize,
) -> (
    tempfile::TempDir,
    PreparedLocalnet,
    RetainedCustodyEnrollment,
) {
    let temporary = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet_at(
        "discovery-activation",
        &temporary.path().join("generation"),
        &ports,
        LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(600);
    let mut parent = ManagedServiceBootstrap::open(&prepared).unwrap();
    let authorization = parent
        .authorize_generated_startup(
            deadline,
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        )
        .unwrap()
        .unwrap();
    let aggregate = parent.selected_policies().unwrap();
    let provider = aggregate.providers[slot].provider_id;
    let policies = aggregate.provider(provider).unwrap();
    let enrollment = policies
        .initial_enrollment(
            crate::managed::native_operation::now_ms().unwrap(),
            authorization.test_terms().signing_deadline_unix_ms,
        )
        .unwrap();
    drop(parent);
    let authority =
        ServiceAuthority::open_network(&prepared, NetworkPurpose::BuildRegistry).unwrap();
    let mut native = NativeFixture::from_generated(&prepared, &authority);
    let log = quote_instructions(
        &native,
        &authority.config,
        [InstructionBox::from(Log::new(
            iroha_data_model::Level::INFO,
            "native enrollment selection prerequisites".into(),
        ))],
    );
    assert_eq!(native.chain.commit(vec![log]), vec![true]);
    drop(authority);
    drop(ports);
    let asset = AssetDefinitionId::parse_address_literal(
        crate::genesis::profile::TAIRA_XOR_ASSET_DEFINITION_ID,
    )
    .unwrap();
    let options = BoundedTransactionOptions {
        fee_payment: FeePaymentIntent::authority(Vec::new(), None),
        max_total_fees: BTreeMap::from([(asset, Quantity::from(1_000u64))]),
        deadline,
    };
    let mut owner = ManagedStreamTokenCustody::open(&prepared, provider).unwrap();
    assert_eq!(
        owner
            .bootstrap_native_configure(
                &mut native,
                &policies.custody,
                enrollment.deadline_unix_ms,
                &options,
            )
            .finalized
            .unwrap()
            .height,
        3,
    );
    assert_eq!(
        owner
            .bootstrap_native_enroll(&mut native, &policies.custody, enrollment, &options,)
            .finalized
            .unwrap()
            .height,
        4,
    );
    let selected = owner
        .retained_initial_enrollment(&policies.custody, enrollment, deadline)
        .unwrap();
    (temporary, prepared, selected)
}

#[test]
fn activation_discovery_scope_deadline_and_carrier_mismatch_make_no_http() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared, enrollment) = enrolled(2);
    let provider = prepared
        .stream_token_authorities()
        .unwrap()
        .unwrap()
        .providers[2]
        .provider_id;
    let mut peers = UnavailablePeers::start(&prepared);
    let required = *enrollment.finalized();
    let deadline = Instant::now() + Duration::from_secs(30);
    let below = ManagedTransactionFinality {
        height: required.height - 1,
        ..required
    };
    assert!(observe_generated_service(&prepared, provider, &enrollment, below, deadline).is_err());
    let foreign_tx = ManagedTransactionFinality {
        transaction_hash: iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(
            b"comparison-only-foreign-tx",
        )),
        ..required
    };
    assert!(
        observe_generated_service(&prepared, provider, &enrollment, foreign_tx, deadline).is_err()
    );
    assert!(
        observe_generated_service(&prepared, provider, &enrollment, required, Instant::now())
            .is_err()
    );
    let mut foreign = prepared.clone();
    foreign.context.dataspace_id = 1;
    assert!(
        observe_generated_service(&foreign, provider, &enrollment, required, deadline).is_err()
    );
    let other = prepared
        .stream_token_authorities()
        .unwrap()
        .unwrap()
        .providers[0]
        .provider_id;
    assert!(observe_generated_service(&prepared, other, &enrollment, required, deadline).is_err());
    let mut unknown = *provider.as_bytes();
    unknown[0] ^= 1;
    assert!(
        observe_generated_service(
            &prepared,
            ProviderId::new(unknown),
            &enrollment,
            required,
            deadline
        )
        .is_err()
    );
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

#[test]
fn unavailable_current_proof_preserves_exact_original_enrollment_and_parent() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared, enrollment) = enrolled(2);
    let provider = prepared
        .stream_token_authorities()
        .unwrap()
        .unwrap()
        .providers[2]
        .provider_id;
    let parent_path = prepared
        .context
        .client_config
        .parent()
        .unwrap()
        .join("runtime/service-operations/network/service-bootstrap/initial/original.nrt");
    let original = iroha_fs::read_private(&parent_path, 512 * 1024).unwrap();
    let mut peers = UnavailablePeers::start(&prepared);
    assert!(
        observe_generated_service(
            &prepared,
            provider,
            &enrollment,
            *enrollment.finalized(),
            Instant::now() + Duration::from_secs(5),
        )
        .is_err()
    );
    peers.finish();
    let requests = peers.requests.lock().unwrap();
    assert!(!requests.is_empty());
    assert!(requests.iter().all(|request| request.method == "GET"));
    assert_eq!(
        iroha_fs::read_private(&parent_path, 512 * 1024)
            .unwrap()
            .as_slice(),
        original.as_slice()
    );
    let parent = ManagedServiceBootstrap::open(&prepared).unwrap();
    let aggregate = parent.selected_policies().unwrap();
    let policies = aggregate.provider(provider).unwrap();
    drop(parent);
    let owner = ManagedStreamTokenCustody::open(&prepared, provider).unwrap();
    let interval = owner
        .inspect_local_initial_interval(&policies.custody)
        .unwrap();
    let replay = owner
        .retained_initial_enrollment(
            &policies.custody,
            interval,
            Instant::now() + Duration::from_secs(30),
        )
        .unwrap();
    assert_eq!(replay.bytes(), enrollment.bytes());
    assert_eq!(replay.finalized(), enrollment.finalized());
    assert_eq!(replay.record_digest(), enrollment.record_digest());
}

#[test]
fn generated_service_observation_keeps_independent_custody_from_live_archive_clients() {
    use iroha_fs::{PrivateDirectory, PublishMode};

    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared, enrollment) = enrolled(2);
    let provider = prepared
        .stream_token_authorities()
        .unwrap()
        .unwrap()
        .providers[2]
        .provider_id;
    let required = *enrollment.finalized();
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut peers = UnavailablePeers::start(&prepared);
    let (config, transport) = prepare(prepared.clone(), deadline).unwrap().unwrap();
    let client = transport.build_client().unwrap();
    drop(transport);
    // A materialized archive client still pins its original exclusive discovery journal.
    assert!(ServiceAuthority::open_network(&prepared, NetworkPurpose::BuildRegistry).is_err());
    assert!(peers.requests.lock().unwrap().is_empty());
    let observer =
        ServiceAuthority::open_network(&prepared, NetworkPurpose::ServiceObservation).unwrap();
    assert_eq!(observer.config.network_id, config.network_id);
    assert_eq!(observer.config.chain, config.chain);
    assert_eq!(observer.config.account, config.account);
    observer.validate_profile().unwrap();
    let observation_path = observer.directory.path().to_path_buf();
    let observation_identity = observer.directory.identity().unwrap();
    let observation_lock = iroha_fs::FileIdentity::of(&observer._lock).unwrap();
    assert_eq!(observation_path.file_name().unwrap(), "service-observation");
    let registry =
        PrivateDirectory::open_exact(observation_path.parent().unwrap().join("build-registry"))
            .unwrap();
    assert_ne!(registry.identity().unwrap(), observation_identity);
    assert_ne!(
        iroha_fs::FileIdentity::of(&registry.open_read("operation.lock").unwrap()).unwrap(),
        observation_lock,
    );
    let registry_names = registry.entries(8).unwrap();
    // Ownership remains exclusive within the observation purpose; this cannot be treated as
    // current proof or a reentrant lock merely because an unrelated archive client exists.
    assert!(matches!(
        observe_generated_service(&prepared, provider, &enrollment, required, deadline),
        Err(Error::Invalid(message))
            if message == "another managed native operation holds this generation"
    ));
    assert!(peers.requests.lock().unwrap().is_empty());
    drop(observer);

    // The actual production observation can now contact its native peers while the archive
    // client remains alive. Unavailable finality still refuses readiness; lock separation
    // supplies no substitute proof, enrollment, or current-service result.
    assert!(matches!(
        observe_generated_service(
            &prepared,
            provider,
            &enrollment,
            required,
            Instant::now() + Duration::from_secs(5),
        ),
        Err(Error::Invalid(message))
            if message == "fresh native generated provider discovery is unavailable"
    ));
    let requests = peers.requests.lock().unwrap();
    assert!(!requests.is_empty());
    assert!(requests.iter().all(|request| request.method == "GET"));
    let requests_before_change = requests.len();
    drop(requests);
    assert_eq!(registry.entries(8).unwrap(), registry_names);
    assert!(ServiceAuthority::open_network(&prepared, NetworkPurpose::BuildRegistry).is_err());
    // The bounded observation dropped its lock even on native-source refusal, while retaining
    // the same original private journal identity for the following observation.
    let observer =
        ServiceAuthority::open_network(&prepared, NetworkPurpose::ServiceObservation).unwrap();
    assert_eq!(observer.directory.identity().unwrap(), observation_identity);
    assert_eq!(
        iroha_fs::FileIdentity::of(&observer._lock).unwrap(),
        observation_lock
    );
    let generation =
        PrivateDirectory::open_exact(prepared.context.client_config.parent().unwrap()).unwrap();
    let original = generation.read("peer0.toml", 1024 * 1024).unwrap();
    generation
        .write_atomic(
            "peer0.toml",
            b"changed original profile",
            PublishMode::Replace,
        )
        .unwrap();
    assert!(observer.validate_profile().is_err());
    assert!(
        observe_generated_service(&prepared, provider, &enrollment, required, deadline).is_err()
    );
    assert_eq!(peers.requests.lock().unwrap().len(), requests_before_change);
    generation
        .write_atomic("peer0.toml", &original, PublishMode::Replace)
        .unwrap();
    observer.validate_profile().unwrap();
    drop(observer);
    drop(client);
    let registry_owner =
        ServiceAuthority::open_network(&prepared, NetworkPurpose::BuildRegistry).unwrap();
    let observer =
        ServiceAuthority::open_network(&prepared, NetworkPurpose::ServiceObservation).unwrap();
    registry_owner.validate_profile().unwrap();
    observer.validate_profile().unwrap();
    assert_ne!(
        registry_owner.directory.identity().unwrap(),
        observer.directory.identity().unwrap()
    );
    peers.finish();
}
