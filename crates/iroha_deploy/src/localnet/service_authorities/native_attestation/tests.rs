//! Genuine generated custody and original-profile controls; no worker or native finality claim.
use super::*;

fn prepare(
    profile: LocalnetServiceProfile,
) -> (
    crate::localnet::localnet_test_helpers::PrivateTempDir,
    PreparedLocalnet,
) {
    let temp = crate::localnet::localnet_test_helpers::private_tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = prepare_localnet_at(
        "attestation-initial",
        &temp.path().join("generation"),
        &ports,
        profile,
        None,
    )
    .unwrap();
    (temp, prepared)
}
fn storage(prepared: &PreparedLocalnet, index: usize) -> PathBuf {
    let peer = &prepared.peers[index];
    let bytes = iroha_fs::read_private(&peer.config_path, 1024 * 1024).unwrap();
    let actual = parse_localnet_peer_config(
        std::str::from_utf8(&bytes).unwrap(),
        Some(&peer.config_path),
    )
    .unwrap();
    assert!(!actual.torii.sorafs_storage.enabled);
    assert!(
        actual
            .torii
            .sorafs_storage
            .provider_ingest_runtime
            .is_none()
    );
    actual.torii.sorafs_storage.data_dir
}

#[test]
fn fresh_global_initializes_exact_policy_once_and_profile_reads_do_not_take_live_lock() {
    let _guard = crate::managed::native_test_guard();
    let (_temp, prepared) = prepare(LocalnetServiceProfile::StreamTokenAuthorities);
    let plan = prepared
        .provider_service_plans()
        .map(|plans| plans.map(|[first, _, _]| first))
        .unwrap()
        .unwrap();
    let root = storage(&prepared, 0);
    assert_eq!(crate::localnet::service_authorities::RetainedProviderServicePlan::attestation_journal_policy(), policy());
    let native = NativeMusubiProviderAttestationCustodyV1::open(
        &root,
        plan.network_id(),
        plan.provider_id(),
        policy(),
    )
    .unwrap();
    // A live owner may coexist with immutable original validation; that validation is not open.
    assert!(
        prepared
            .provider_service_plans()
            .map(|plans| plans.map(|[first, _, _]| first))
            .unwrap()
            .is_some()
    );
    assert!(prepared.stream_token_authorities().unwrap().is_some());
    assert!(
        NativeMusubiProviderAttestationCustodyV1::open(
            &root,
            plan.network_id(),
            plan.provider_id(),
            policy()
        )
        .is_err()
    );
    assert!(
        NativeMusubiProviderAttestationCustodyV1::initialize(
            &root,
            plan.network_id(),
            plan.provider_id(),
            policy()
        )
        .is_err()
    );
    let plans = prepared.provider_service_plans().unwrap().unwrap();
    for (index, other) in plans.iter().enumerate().skip(1) {
        let other_root = storage(&prepared, index);
        assert!(other_root.join("provider-attestation-native").exists());
        NativeMusubiProviderAttestationCustodyV1::open(
            &other_root,
            other.network_id(),
            other.provider_id(),
            policy(),
        )
        .unwrap();
        assert!(
            NativeMusubiProviderAttestationCustodyV1::open(
                &other_root,
                plan.network_id(),
                plan.provider_id(),
                policy()
            )
            .is_err()
        );
    }
    assert!(
        !storage(&prepared, 3)
            .join("provider-attestation-native")
            .exists()
    );
    drop(native);
    NativeMusubiProviderAttestationCustodyV1::open(
        &root,
        plan.network_id(),
        plan.provider_id(),
        policy(),
    )
    .unwrap();
}

#[test]
fn standard_generation_has_no_attestation_plan_or_history() {
    let _guard = crate::managed::native_test_guard();
    let (_temp, prepared) = prepare(LocalnetServiceProfile::Standard);
    assert!(
        prepared
            .provider_service_plans()
            .map(|plans| plans.map(|[first, _, _]| first))
            .unwrap()
            .is_none()
    );
    for index in 0..4 {
        assert!(
            !storage(&prepared, index)
                .join("provider-attestation-native")
                .exists()
        );
    }
}

#[test]
fn original_reads_never_recreate_missing_or_corrupt_native_history() {
    let _guard = crate::managed::native_test_guard();
    let (_temp, prepared) = prepare(LocalnetServiceProfile::StreamTokenAuthorities);
    let plan = prepared
        .provider_service_plans()
        .map(|plans| plans.map(|[first, _, _]| first))
        .unwrap()
        .unwrap();
    let root = storage(&prepared, 0);
    let history =
        iroha_fs::PrivateDirectory::open(root.join("provider-attestation-native")).unwrap();
    let original = history.read("journal.nrt", 1024 * 1024).unwrap();
    history
        .write_atomic(
            "journal.nrt",
            b"invalid retained journal",
            iroha_fs::PublishMode::Replace,
        )
        .unwrap();
    assert!(
        prepared
            .provider_service_plans()
            .map(|plans| plans.map(|[first, _, _]| first))
            .unwrap()
            .is_some()
    );
    assert!(
        NativeMusubiProviderAttestationCustodyV1::open(
            &root,
            plan.network_id(),
            plan.provider_id(),
            policy()
        )
        .is_err()
    );
    assert_eq!(
        history.read("journal.nrt", 1024).unwrap().as_slice(),
        b"invalid retained journal"
    );
    history
        .write_atomic("journal.nrt", &original, iroha_fs::PublishMode::Replace)
        .unwrap();
    std::fs::remove_file(history.path().join("journal.nrt")).unwrap();
    assert!(
        prepared
            .provider_service_plans()
            .map(|plans| plans.map(|[first, _, _]| first))
            .unwrap()
            .is_some()
    );
    assert!(
        NativeMusubiProviderAttestationCustodyV1::open(
            &root,
            plan.network_id(),
            plan.provider_id(),
            policy()
        )
        .is_err()
    );
    assert!(!history.path().join("journal.nrt").exists());
}
