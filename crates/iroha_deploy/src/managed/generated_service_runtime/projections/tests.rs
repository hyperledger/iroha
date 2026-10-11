//! Real retained-owner projection parity, source refusal and physical admission controls.

use super::*;
use crate::localnet::{LocalnetServiceProfile, service_authorities::count_profile_validations};
use norito::core::DecodeBudgetContext;
use std::net::TcpListener;

type Projections = (
    [RetainedProviderServicePlan; 3],
    Vec<RetainedProviderServicePlan>,
    Vec<RetainedGatewayCompliancePlan>,
);

fn prepared(root: &Path, name: &str, profile: LocalnetServiceProfile) -> PreparedLocalnet {
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    crate::localnet::prepare_localnet_at(name, root, &ports, profile, None).unwrap()
}

fn fixture() -> (tempfile::TempDir, GeneratedServiceRuntime, Vec<TcpListener>) {
    let temporary = tempfile::tempdir().unwrap();
    let prepared = prepared(
        &temporary.path().join("generation"),
        "runtime-original-projections",
        LocalnetServiceProfile::StreamTokenAuthorities,
    );
    let peers = prepared
        .peers
        .iter()
        .map(|peer| {
            let url: url::Url = peer.torii_url.parse().unwrap();
            let listener = TcpListener::bind(("127.0.0.1", url.port().unwrap())).unwrap();
            listener.set_nonblocking(true).unwrap();
            listener
        })
        .collect();
    let owner = GeneratedServiceRuntime::open(&prepared).unwrap();
    (temporary, owner, peers)
}

fn no_http(peers: &[TcpListener]) {
    for peer in peers {
        assert_eq!(
            peer.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}

fn absolute(prepared: &PreparedLocalnet) -> Result<Projections> {
    let plans = prepared.provider_service_plans()?.unwrap();
    let mut individual = Vec::new();
    let mut compliance = Vec::new();
    for plan in &plans {
        individual.push(prepared.provider_service_plan(plan.provider_id())?.unwrap());
        compliance.push(
            prepared
                .gateway_compliance_plan(plan.provider_id())?
                .unwrap(),
        );
    }
    Ok((plans, individual, compliance))
}

fn borrowed(owner: &GeneratedServiceRuntime) -> Result<Projections> {
    let prepared = &owner.authority.prepared;
    let plans = owner.original_provider_plans(prepared)?.unwrap();
    let mut individual = Vec::new();
    let mut compliance = Vec::new();
    for plan in &plans {
        individual.push(
            owner
                .original_provider_plan(prepared, plan.provider_id())?
                .unwrap(),
        );
        compliance.push(
            owner
                .original_gateway_compliance_plan(prepared, plan.provider_id())?
                .unwrap(),
        );
    }
    Ok((plans, individual, compliance))
}

fn same_plan(actual: &RetainedProviderServicePlan, expected: &RetainedProviderServicePlan) {
    assert_eq!(actual.network_id(), expected.network_id());
    assert_eq!(actual.provider_id(), expected.provider_id());
    assert_eq!(actual.slot(), expected.slot());
    assert_eq!(actual.peer_index(), expected.peer_index());
    assert_eq!(
        actual.original_profile_commitment(),
        expected.original_profile_commitment()
    );
    assert_eq!(actual.reserve_terms(), expected.reserve_terms());
    assert_eq!(actual.pricing(), expected.pricing());
    assert_eq!(actual.declaration(), expected.declaration());
    assert_eq!(actual.admission_material(), expected.admission_material());
    assert_eq!(actual.https_origin(), expected.https_origin());
}

fn same(actual: &Projections, expected: &Projections) {
    for (actual, expected) in actual.0.iter().zip(&expected.0) {
        same_plan(actual, expected);
    }
    assert_eq!(actual.1.len(), 3);
    assert_eq!(actual.2.len(), 3);
    for (actual, expected) in actual.1.iter().zip(&expected.1) {
        same_plan(actual, expected);
    }
    for (actual, expected) in actual.2.iter().zip(&expected.2) {
        assert_eq!(actual.network_id(), expected.network_id());
        assert_eq!(actual.provider_id(), expected.provider_id());
        assert_eq!(actual.manager(), expected.manager());
        assert_eq!(actual.gateway_label(), expected.gateway_label());
        assert_eq!(actual.gateway_id(), expected.gateway_id());
        assert_eq!(actual.trust_policy(), expected.trust_policy());
        assert_eq!(actual.original_commitment(), expected.original_commitment());
        assert_eq!(
            actual.empty_feed_transport_digest(),
            expected.empty_feed_transport_digest()
        );
        assert_eq!(actual.issued_at_unix(), expected.issued_at_unix());
        assert_eq!(actual.expires_at_unix(), expected.expires_at_unix());
    }
}

#[test]
fn original_gateway_projections_match_standalone_without_recapturing() {
    let _resources = crate::managed::native_test_guard();
    let (temporary, mut owner, peers) = fixture();
    let prepared = &owner.authority.prepared;
    let (expected, captures) = count_profile_validations(|| absolute(prepared));
    let expected = expected.unwrap();
    assert_eq!(captures, 7);
    let (actual, captures) = count_profile_validations(|| borrowed(&owner));
    same(&actual.unwrap(), &expected);
    assert_eq!(captures, 0);
    // Typed original plans cannot be replaced by mutable owner projections.
    let original_config = owner.authority.config.clone();
    let original_genesis = owner.authority.genesis.clone();
    owner.authority.config.chain = "00000000-0000-0000-0000-000000000001".parse().unwrap();
    owner.authority.config.network_id = NetworkId::from_genesis_hash(
        iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(b"mutable projection")),
    );
    owner
        .authority
        .genesis
        .chain_id
        .push_str("-mutable-projection");
    owner.authority.peers.reverse();
    same(&borrowed(&owner).unwrap(), &expected);
    owner.authority.config = original_config;
    owner.authority.genesis = original_genesis;
    owner.authority.peers.reverse();
    let prepared = &owner.authority.prepared;
    let unknown = ProviderId::new([0xAB; 32]);
    assert_eq!(
        owner
            .original_provider_plan(prepared, unknown)
            .err()
            .unwrap()
            .to_string(),
        prepared
            .provider_service_plan(unknown)
            .err()
            .unwrap()
            .to_string(),
    );
    assert_eq!(
        owner
            .original_gateway_compliance_plan(prepared, unknown)
            .err()
            .unwrap()
            .to_string(),
        prepared
            .gateway_compliance_plan(unknown)
            .err()
            .unwrap()
            .to_string(),
    );
    let standard = self::prepared(
        &temporary.path().join("standard"),
        "projection-standard",
        LocalnetServiceProfile::Standard,
    );
    assert!(standard.provider_service_plans().unwrap().is_none());
    assert!(
        standard
            .provider_service_plan(expected.0[0].provider_id())
            .unwrap()
            .is_none()
    );
    assert!(
        standard
            .gateway_compliance_plan(expected.0[0].provider_id())
            .unwrap()
            .is_none()
    );
    let mut foreign = prepared.clone();
    foreign.context.network_id.push_str("-foreign");
    for selected in [&standard, &foreign] {
        for error in [
            owner.original_provider_plans(selected).err().unwrap(),
            owner
                .original_provider_plan(selected, expected.0[0].provider_id())
                .err()
                .unwrap(),
            owner
                .original_gateway_compliance_plan(selected, expected.0[0].provider_id())
                .err()
                .unwrap(),
        ] {
            assert!(matches!(error, crate::managed::Error::Invalid(message)
                if message == "generated runtime projection belongs to another prepared generation"));
        }
    }
    no_http(&peers);
}

#[test]
fn original_gateway_projections_refuse_changed_image_and_lock_then_restore() {
    let _resources = crate::managed::native_test_guard();
    let (temporary, owner, peers) = fixture();
    let expected = borrowed(&owner).unwrap();
    let prepared = &owner.authority.prepared;
    let generation = PrivateDirectory::open_exact(generation_path(prepared).unwrap()).unwrap();
    let original = generation.read("peer3.toml", MAX_CONFIG_BYTES).unwrap();
    let mut changed = Zeroizing::new(original.to_vec());
    changed.extend_from_slice(b"\n# changed original projection source\n");
    crate::secret_toml::parse_table(std::str::from_utf8(&changed).unwrap(), "changed peer")
        .unwrap();
    generation
        .write_atomic("peer3.toml", &changed, PublishMode::Replace)
        .unwrap();
    let provider = expected.0[0].provider_id();
    assert!(owner.original_provider_plans(prepared).is_err());
    assert!(owner.original_provider_plan(prepared, provider).is_err());
    assert!(
        owner
            .original_gateway_compliance_plan(prepared, provider)
            .is_err()
    );
    generation
        .write_atomic("peer3.toml", &original, PublishMode::Replace)
        .unwrap();
    same(&borrowed(&owner).unwrap(), &expected);
    let missing = generation.path().join("peer3.toml");
    let displaced_peer = temporary.path().join("displaced-peer.toml");
    std::fs::rename(&missing, &displaced_peer).unwrap();
    assert!(owner.original_provider_plans(prepared).is_err());
    assert!(owner.original_provider_plan(prepared, provider).is_err());
    assert!(
        owner
            .original_gateway_compliance_plan(prepared, provider)
            .is_err()
    );
    std::fs::rename(&displaced_peer, &missing).unwrap();
    same(&borrowed(&owner).unwrap(), &expected);
    // The real view's ordinary-error exit still closes the original image.
    let intent = owner
        .authority
        .original_intent_if_shared()
        .unwrap()
        .unwrap();
    assert!(intent.provider_plan(ProviderId::new([0xAC; 32])).is_err());
    generation
        .write_atomic("peer3.toml", &changed, PublishMode::Replace)
        .unwrap();
    assert!(intent.finish().is_err());
    generation
        .write_atomic("peer3.toml", &original, PublishMode::Replace)
        .unwrap();
    let directory_id = owner.authority.directory.identity().unwrap();
    let lock_id = iroha_fs::FileIdentity::of(&owner.authority._lock).unwrap();
    let lock = owner.authority.directory.path().join("operation.lock");
    let displaced = owner.authority.directory.path().join("displaced.lock");
    #[cfg(unix)]
    {
        std::fs::rename(&lock, &displaced).unwrap();
        assert!(borrowed(&owner).is_err());
        let replacement = owner
            .authority
            .directory
            .open_lock("operation.lock")
            .unwrap();
        assert!(borrowed(&owner).is_err());
        drop(replacement);
        owner
            .authority
            .directory
            .remove_private("operation.lock")
            .unwrap();
        std::fs::rename(&displaced, &lock).unwrap();
    }
    #[cfg(windows)]
    {
        assert!(std::fs::rename(&lock, &displaced).is_err());
    }
    same(&borrowed(&owner).unwrap(), &expected);
    assert_eq!(owner.authority.directory.identity().unwrap(), directory_id);
    assert_eq!(
        iroha_fs::FileIdentity::of(&owner.authority._lock).unwrap(),
        lock_id
    );
    no_http(&peers);
}

#[test]
fn original_gateway_projections_keep_active_and_owned_full_admission() {
    fn limits(allocated: usize) -> norito::DecodeLimits {
        let finite = 64 * 1024 * 1024;
        norito::DecodeLimits::new(finite, finite, finite, allocated, 64)
    }
    let _resources = crate::managed::native_test_guard();
    let (_temporary, owner, peers) = fixture();
    let prepared = &owner.authority.prepared;
    let (warm, captures) = count_profile_validations(|| borrowed(&owner));
    let warm = warm.unwrap();
    assert_eq!(captures, 0);
    let baseline = DecodeBudgetContext::new(limits(64 * 1024 * 1024));
    let (expected, captures) = count_profile_validations(|| baseline.with(|| absolute(prepared)));
    let expected = expected.unwrap();
    assert_eq!(captures, 7);
    let charge = usize::try_from(baseline.consumed_allocated_bytes()).unwrap();
    assert!(charge > 0);
    let exact = DecodeBudgetContext::new(limits(charge));
    let (actual, captures) = count_profile_validations(|| exact.with(|| borrowed(&owner)));
    same(&actual.unwrap(), &expected);
    assert_eq!(captures, 7);
    assert_eq!(
        exact.consumed_allocated_bytes(),
        baseline.consumed_allocated_bytes()
    );
    for allocated in [0, charge - 1] {
        let context = DecodeBudgetContext::new(limits(allocated));
        let (expected, expected_captures) =
            count_profile_validations(|| context.with(|| absolute(prepared)));
        let context = DecodeBudgetContext::new(limits(allocated));
        let (actual, captures) = count_profile_validations(|| context.with(|| borrowed(&owner)));
        assert_eq!(
            actual.err().unwrap().to_string(),
            expected.err().unwrap().to_string()
        );
        assert_eq!(captures, expected_captures);
    }
    // Use the renderer's actual purpose after releasing its former native owner.
    let prepared = prepared.clone();
    drop(owner);
    let construction = DecodeBudgetContext::new(limits(64 * 1024 * 1024));
    let (owned, captures) = count_profile_validations(|| {
        construction.with(|| GeneratedServiceRuntime::open(&prepared))
    });
    let owned = owned.unwrap();
    assert_eq!(captures, 1);
    assert!(
        owned
            .authority
            .original_intent_if_shared()
            .unwrap()
            .is_none()
    );
    let (actual, captures) = count_profile_validations(|| borrowed(&owned));
    same(&actual.unwrap(), &warm);
    assert_eq!(captures, 7);
    no_http(&peers);
}

fn bootstrap_path(owner: &GeneratedServiceRuntime) -> PathBuf {
    owner
        .authority
        .directory
        .path()
        .parent()
        .unwrap()
        .join("service-bootstrap")
}

fn bootstrap_policies(parent: &ManagedServiceBootstrap) -> Vec<u8> {
    norito::encode_canonical(&parent.selected_policies().unwrap()).unwrap()
}

fn seed_bootstrap(owner: &GeneratedServiceRuntime) -> Vec<u8> {
    use iroha_data_model::{asset::AssetDefinitionId, transaction::FeePaymentIntent};
    use iroha_primitives::numeric::Quantity;
    use iroha_wallet::operations::BoundedTransactionOptions;
    let options = BoundedTransactionOptions {
        fee_payment: FeePaymentIntent::authority(Vec::new(), None),
        max_total_fees: std::collections::BTreeMap::from([(
            AssetDefinitionId::parse_address_literal(
                crate::genesis::profile::TAIRA_XOR_ASSET_DEFINITION_ID,
            )
            .unwrap(),
            Quantity::from(1_000u64),
        )]),
        deadline: Instant::now() + std::time::Duration::from_secs(30),
    };
    let mut parent = ManagedServiceBootstrap::open(&owner.authority.prepared).unwrap();
    assert!(parent.authorize_test_startup(&options).unwrap().is_some());
    bootstrap_policies(&parent)
}

#[test]
fn original_bootstrap_reopen_matches_selected_original_without_recapturing() {
    use crate::managed::service_authority::profile_validation_test_support;
    let _resources = crate::managed::native_test_guard();
    let (_temporary, mut owner, peers) = fixture();
    let expected = seed_bootstrap(&owner);
    let prepared = owner.authority.prepared.clone();
    let (ordinary, captures) =
        count_profile_validations(|| ManagedServiceBootstrap::open(&prepared));
    let ordinary = ordinary.unwrap();
    assert_eq!(captures, 1);
    assert_eq!(bootstrap_policies(&ordinary), expected);
    // The exact ordinary Bootstrap lock must prevent borrowed admission. Four actual
    // renderer checks include both closing passes despite the child's ordinary refusal.
    let (refused, validations) =
        profile_validation_test_support::count(|| owner.open_original_bootstrap(&prepared));
    assert!(refused.is_err());
    assert_eq!(validations, 4);
    drop(ordinary);
    let (borrowed, captures) =
        count_profile_validations(|| owner.open_original_bootstrap(&prepared));
    let borrowed = borrowed.unwrap();
    assert_eq!(captures, 0);
    assert_eq!(bootstrap_policies(&borrowed), expected);
    assert!(ManagedServiceBootstrap::open(&prepared).is_err());
    drop(borrowed);
    // Mutable renderer projections cannot alter the child constructor's immutable intent.
    let config = owner.authority.config.clone();
    let genesis = owner.authority.genesis.clone();
    owner.authority.config.chain = "00000000-0000-0000-0000-000000000001".parse().unwrap();
    owner
        .authority
        .genesis
        .chain_id
        .push_str("-mutable-projection");
    owner.authority.peers.reverse();
    let parent = owner.open_original_bootstrap(&prepared).unwrap();
    assert_eq!(bootstrap_policies(&parent), expected);
    drop(parent);
    owner.authority.config = config;
    owner.authority.genesis = genesis;
    owner.authority.peers.reverse();
    let mut foreign = prepared.clone();
    foreign.context.network_id.push_str("-foreign");
    let (refused, captures) = count_profile_validations(|| owner.open_original_bootstrap(&foreign));
    assert!(
        matches!(refused, Err(crate::managed::Error::Invalid(message)) if message == "generated runtime bootstrap belongs to another prepared generation")
    );
    assert_eq!(captures, 0);
    no_http(&peers);
}

#[test]
fn original_bootstrap_reopen_refuses_missing_original_or_purpose_then_restores() {
    use crate::managed::service_authority::profile_validation_test_support;
    let _resources = crate::managed::native_test_guard();
    let (temporary, owner, peers) = fixture();
    let expected = seed_bootstrap(&owner);
    let prepared = &owner.authority.prepared;
    let generation = PrivateDirectory::open_exact(generation_path(prepared).unwrap()).unwrap();
    let peer = generation.path().join("peer3.toml");
    let displaced_peer = temporary.path().join("displaced-bootstrap-peer.toml");
    std::fs::rename(&peer, &displaced_peer).unwrap();
    assert!(owner.open_original_bootstrap(prepared).is_err());
    std::fs::rename(&displaced_peer, &peer).unwrap();
    let parent = owner.open_original_bootstrap(prepared).unwrap();
    assert_eq!(bootstrap_policies(&parent), expected);
    drop(parent);
    let path = bootstrap_path(&owner);
    let directory = PrivateDirectory::open_exact(&path).unwrap();
    let directory_id = directory.identity().unwrap();
    let initial = directory.open_child("initial").unwrap();
    let original = initial.read("original.nrt", MAX_POLICY_BYTES).unwrap();
    assert!(initial.remove_private("original.nrt").unwrap());
    let parent = owner.open_original_bootstrap(prepared).unwrap();
    assert!(parent.selected_policies().is_err());
    assert!(
        initial
            .read_optional("original.nrt", MAX_POLICY_BYTES)
            .unwrap()
            .is_none()
    );
    drop(parent);
    initial
        .write_atomic("original.nrt", &original, PublishMode::CreateNew)
        .unwrap();
    assert_eq!(
        bootstrap_policies(&owner.open_original_bootstrap(prepared).unwrap()),
        expected
    );
    // Runtime polling must not recreate a missing Bootstrap purpose. Initial creation
    // remains the earlier prepare boundary; restored same-object custody can be retried.
    let displaced = path.parent().unwrap().join("displaced-service-bootstrap");
    #[cfg(unix)]
    {
        std::fs::rename(&path, &displaced).unwrap();
        let (refused, validations) =
            profile_validation_test_support::count(|| owner.open_original_bootstrap(prepared));
        assert!(
            matches!(refused, Err(crate::managed::Error::Invalid(message)) if message == "original service bootstrap purpose is absent")
        );
        assert_eq!(validations, 4);
        assert!(!path.exists());
        std::fs::rename(&displaced, &path).unwrap();
    }
    #[cfg(windows)]
    {
        assert!(std::fs::rename(&path, &displaced).is_err());
    }
    assert_eq!(directory.identity().unwrap(), directory_id);
    assert_eq!(
        bootstrap_policies(&owner.open_original_bootstrap(prepared).unwrap()),
        expected
    );
    // A lost or replaced retained renderer lock cannot be used to admit a sibling owner.
    let lock = owner.authority.directory.path().join("operation.lock");
    let displaced_lock = owner
        .authority
        .directory
        .path()
        .join("displaced-bootstrap-renderer.lock");
    let lock_id = iroha_fs::FileIdentity::of(&owner.authority._lock).unwrap();
    #[cfg(unix)]
    {
        std::fs::rename(&lock, &displaced_lock).unwrap();
        assert!(owner.open_original_bootstrap(prepared).is_err());
        let replacement = owner
            .authority
            .directory
            .open_lock("operation.lock")
            .unwrap();
        assert!(owner.open_original_bootstrap(prepared).is_err());
        drop(replacement);
        owner
            .authority
            .directory
            .remove_private("operation.lock")
            .unwrap();
        std::fs::rename(&displaced_lock, &lock).unwrap();
    }
    #[cfg(windows)]
    {
        assert!(std::fs::rename(&lock, &displaced_lock).is_err());
    }
    assert_eq!(
        iroha_fs::FileIdentity::of(&owner.authority._lock).unwrap(),
        lock_id
    );
    assert_eq!(
        bootstrap_policies(&owner.open_original_bootstrap(prepared).unwrap()),
        expected
    );
    no_http(&peers);
}

#[test]
fn original_bootstrap_reopen_keeps_active_and_owned_full_admission() {
    fn limits(allocated: usize) -> norito::DecodeLimits {
        let finite = 64 * 1024 * 1024;
        norito::DecodeLimits::new(finite, finite, finite, allocated, 64)
    }
    let _resources = crate::managed::native_test_guard();
    let (_temporary, owner, peers) = fixture();
    let expected = seed_bootstrap(&owner);
    let prepared = owner.authority.prepared.clone();
    let (warm, captures) = count_profile_validations(|| owner.open_original_bootstrap(&prepared));
    assert_eq!(bootstrap_policies(&warm.unwrap()), expected);
    assert_eq!(captures, 0);
    let baseline = DecodeBudgetContext::new(limits(64 * 1024 * 1024));
    let (ordinary, captures) =
        count_profile_validations(|| baseline.with(|| ManagedServiceBootstrap::open(&prepared)));
    assert_eq!(bootstrap_policies(&ordinary.unwrap()), expected);
    assert_eq!(captures, 1);
    let charge = usize::try_from(baseline.consumed_allocated_bytes()).unwrap();
    assert!(charge > 0);
    let exact = DecodeBudgetContext::new(limits(charge));
    let (borrowed, captures) =
        count_profile_validations(|| exact.with(|| owner.open_original_bootstrap(&prepared)));
    assert_eq!(bootstrap_policies(&borrowed.unwrap()), expected);
    assert_eq!(captures, 1);
    assert_eq!(
        exact.consumed_allocated_bytes(),
        baseline.consumed_allocated_bytes()
    );
    for allocated in [0, charge - 1] {
        let old = DecodeBudgetContext::new(limits(allocated));
        let (ordinary, old_captures) =
            count_profile_validations(|| old.with(|| ManagedServiceBootstrap::open(&prepared)));
        let new = DecodeBudgetContext::new(limits(allocated));
        let (borrowed, captures) =
            count_profile_validations(|| new.with(|| owner.open_original_bootstrap(&prepared)));
        assert_eq!(
            borrowed.err().unwrap().to_string(),
            ordinary.err().unwrap().to_string()
        );
        assert_eq!(captures, old_captures);
        assert_eq!(
            new.consumed_allocated_bytes(),
            old.consumed_allocated_bytes()
        );
    }
    drop(owner);
    let construction = DecodeBudgetContext::new(limits(64 * 1024 * 1024));
    let owned = construction
        .with(|| GeneratedServiceRuntime::open(&prepared))
        .unwrap();
    assert!(
        owned
            .authority
            .original_intent_if_shared()
            .unwrap()
            .is_none()
    );
    let (borrowed, captures) =
        count_profile_validations(|| owned.open_original_bootstrap(&prepared));
    assert_eq!(bootstrap_policies(&borrowed.unwrap()), expected);
    assert_eq!(captures, 1);
    no_http(&peers);
}

#[test]
fn gateway_pair_keeps_callback_error_and_replaced_lock_boundaries() {
    use crate::localnet::service_authorities::count_profile_images;
    use crate::managed::service_authority::profile_validation_test_support::operation_paths;
    use std::cell::Cell;
    let _resources = crate::managed::native_test_guard();
    let (_temporary, owner, peers) = fixture();
    let prepared = &owner.authority.prepared;
    let provider = owner.original_provider_plans(prepared).unwrap().unwrap()[0].provider_id();
    for full in [true, false] {
        let calls = Cell::new(0);
        let run = || {
            owner.validate_gateway_compliance_pair(prepared, provider, || {
                calls.set(calls.get() + 1);
                Err(invalid("ordinary child observation refusal"))
            })
        };
        let ((result, images), locks) = operation_paths(|| {
            count_profile_images(|| {
                if full {
                    GeneratedServiceRuntime::test_full_gateway_pair(run)
                } else {
                    run()
                }
            })
        });
        assert_eq!(
            result.unwrap_err().to_string(),
            "ordinary child observation refusal"
        );
        assert_eq!(calls.get(), 1);
        assert_eq!(images, 2);
        assert_eq!(
            locks.len(),
            4,
            "child error never enters the second projection"
        );
    }
    let lock = owner.authority.directory.path().join("operation.lock");
    let saved = owner.authority.directory.path().join("saved-pair.lock");
    let original_id = iroha_fs::FileIdentity::of(&owner.authority._lock).unwrap();
    for full in [true, false] {
        let run = || {
            owner.validate_gateway_compliance_pair(prepared, provider, || {
                #[cfg(unix)]
                {
                    std::fs::rename(&lock, &saved).unwrap();
                    owner
                        .authority
                        .directory
                        .write_atomic("operation.lock", b"", PublishMode::CreateNew)
                        .unwrap();
                }
                #[cfg(windows)]
                assert!(std::fs::rename(&lock, &saved).is_err());
                Ok(())
            })
        };
        let result = if full {
            GeneratedServiceRuntime::test_full_gateway_pair(run)
        } else {
            run()
        };
        #[cfg(unix)]
        {
            assert_eq!(
                result.unwrap_err().to_string(),
                "managed native operation lock was replaced"
            );
            owner
                .authority
                .directory
                .remove_private("operation.lock")
                .unwrap();
            std::fs::rename(&saved, &lock).unwrap();
        }
        #[cfg(windows)]
        result.unwrap();
        assert_eq!(
            iroha_fs::FileIdentity::of(&owner.authority._lock).unwrap(),
            original_id
        );
        owner
            .validate_gateway_compliance_pair(prepared, provider, || Ok(()))
            .unwrap();
    }
    no_http(&peers);
}

#[test]
fn gateway_pair_preserves_active_decode_and_owned_producers() {
    use crate::managed::service_authority::profile_validation_test_support::operation_paths;
    use std::cell::Cell;
    fn limits(allocated: usize) -> norito::DecodeLimits {
        let finite = 64 * 1024 * 1024;
        norito::DecodeLimits::new(finite, finite, finite, allocated, 64)
    }
    let _resources = crate::managed::native_test_guard();
    let (_temporary, owner, peers) = fixture();
    let provider = owner
        .original_provider_plans(&owner.authority.prepared)
        .unwrap()
        .unwrap()[0]
        .provider_id();
    for allocated in [0, 1, 64 * 1024 * 1024] {
        let run = |full| {
            let context = DecodeBudgetContext::new(limits(allocated));
            let calls = Cell::new(0);
            let ((result, captures), locks) = operation_paths(|| {
                count_profile_validations(|| {
                    context.with(|| {
                        let run = || {
                            owner.validate_gateway_compliance_pair(
                                &owner.authority.prepared,
                                provider,
                                || {
                                    calls.set(calls.get() + 1);
                                    Ok(())
                                },
                            )
                        };
                        if full {
                            GeneratedServiceRuntime::test_full_gateway_pair(run)
                        } else {
                            run()
                        }
                    })
                })
            });
            (
                result.map_err(|error| error.to_string()),
                captures,
                locks,
                calls.get(),
                context.consumed_allocated_bytes(),
            )
        };
        let expected = run(true);
        let actual = run(false);
        assert_eq!(actual.0, expected.0);
        assert_eq!(actual.1, expected.1);
        assert_eq!(actual.2, expected.2);
        assert_eq!(actual.3, expected.3);
        if allocated <= 1 {
            assert!(actual.0.is_err());
            assert_eq!(actual.3, 0);
            assert_eq!(actual.4, expected.4);
        } else {
            assert_eq!(actual.0, Ok(()));
            assert_eq!(actual.1, 2);
            assert_eq!(actual.3, 1);
            assert!(actual.4 > 0 && actual.4 <= allocated as u64);
            assert!(expected.4 > 0 && expected.4 <= allocated as u64);
        }
    }
    let prepared = owner.authority.prepared.clone();
    drop(owner);
    let construction = DecodeBudgetContext::new(limits(64 * 1024 * 1024));
    let owned = construction
        .with(|| GeneratedServiceRuntime::open(&prepared))
        .unwrap();
    assert!(
        owned
            .authority
            .original_intent_if_shared()
            .unwrap()
            .is_none()
    );
    for full in [true, false] {
        let calls = Cell::new(0);
        let (result, captures) = count_profile_validations(|| {
            let run = || {
                owned.validate_gateway_compliance_pair(&prepared, provider, || {
                    calls.set(calls.get() + 1);
                    Ok(())
                })
            };
            if full {
                GeneratedServiceRuntime::test_full_gateway_pair(run)
            } else {
                run()
            }
        });
        result.unwrap();
        assert_eq!(captures, 2);
        assert_eq!(calls.get(), 1);
    }
    no_http(&peers);
}
