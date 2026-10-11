//! Desktop matrix and staging preserve the shared original preset selection.

use super::*;
use iroha_crypto::{Algorithm, KeyPair};
use iroha_deploy::bootstrap::InstalledNetworkProfile;

fn image(name: &str) -> Vec<u8> {
    InstalledNetworkProfiles::new(vec![
        InstalledNetworkProfile::new(
            name.into(),
            KeyPair::from_seed(vec![27; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
            7,
            "https://fixture.invalid/checkpoint.nrt".into(),
        )
        .unwrap(),
    ])
    .unwrap()
    .encode_installation()
    .unwrap()
}

#[test]
fn matrix_cannot_claim_complete_qualification_or_lose_original_profile_custody() {
    let root = tempfile::tempdir().unwrap();
    let selection = network_profiles::development(
        &InstalledNetworkProfiles::from_installation_bytes(&image("fixture")).unwrap(),
    )
    .unwrap();
    let mut result = super::tests::bundle_fixture(root.path(), false, Some(selection));
    let matrix = result.output_root.join("matrix.json");
    super::update_bundle_matrix(&result, &matrix, true).unwrap();
    let value: Value = json::from_slice(&std::fs::read(&matrix).unwrap()).unwrap();
    assert_eq!(
        value["entries"][0]["qualification"].as_str(),
        Some("local_native_diagnostic")
    );
    assert_eq!(
        value["entries"][0]["official_taira_attachment_qualified"].as_bool(),
        Some(false)
    );
    assert_eq!(
        value["entries"][0]["network_profiles"],
        result.network_profiles.as_ref().unwrap().provenance()
    );
    assert_eq!(
        value["entries"][0]["manifest_sha256"].as_str(),
        Some(super::sha256_hex(&std::fs::read(&result.manifest_path).unwrap()).as_str())
    );
    let original = std::fs::read(&matrix).unwrap();
    // Substitute the reported selection, preserving actual original files and owners. Windows
    // denies physical deletion while the original native file custody is retained.
    result.network_profiles = Some(
        network_profiles::development(
            &InstalledNetworkProfiles::from_installation_bytes(&image("changed")).unwrap(),
        )
        .unwrap(),
    );
    assert!(super::update_bundle_matrix(&result, &matrix, true).is_err());
    assert_eq!(std::fs::read(&matrix).unwrap(), original);
    result.network_profiles = None;
    result.profile = "release".into();
    assert!(super::run_bundle_smoke(&result).is_err());
    assert!(super::update_bundle_matrix(&result, &matrix, true).is_err());
    assert_eq!(std::fs::read(&matrix).unwrap(), original);
}

#[test]
fn staging_preserves_existing_outputs_and_publishes_original_profiles_and_archive_once() {
    let root = tempfile::tempdir().unwrap();
    let bytes = image("fixture");
    let selection = network_profiles::development(
        &InstalledNetworkProfiles::from_installation_bytes(&bytes).unwrap(),
    )
    .unwrap();
    let result = super::tests::bundle_fixture(root.path(), true, Some(selection));
    let stage = result.output_root.join("staged");
    let owner = PrivateDirectory::open_or_create(&stage).unwrap();
    let prior = owner.create_child("bundle").unwrap();
    prior
        .write_atomic("kept", b"previous staged bundle", PublishMode::CreateNew)
        .unwrap();
    assert!(super::stage_bundle(&result, &stage).is_err());
    assert_eq!(
        prior.read("kept", 64).unwrap().as_slice(),
        b"previous staged bundle"
    );
    assert_eq!(std::fs::read_dir(&stage).unwrap().count(), 1);
    assert!(!stage.join("bundle.tar.gz").exists());
    let fresh = result.output_root.join("fresh-stage");
    super::stage_bundle(&result, &fresh).unwrap();
    result
        .network_profiles
        .as_ref()
        .unwrap()
        .verify_installed(&NativeBundleLayout::current().profiles_path(&fresh.join("bundle")))
        .unwrap();
    assert_eq!(
        std::fs::read(fresh.join("bundle.tar.gz")).unwrap(),
        b"original archive bytes"
    );
    assert_eq!(
        std::fs::read(NativeBundleLayout::current().profiles_path(&result.bundle_root)).unwrap(),
        bytes,
    );
    assert!(super::stage_bundle(&result, &fresh).is_err());
    drop(super::retained_bundle(&result).unwrap());
}

#[cfg(unix)]
#[test]
fn staging_and_matrix_refuse_original_profile_or_archive_mutations_before_creating_outputs() {
    for mutation in [
        "profile-change",
        "profile-missing",
        "archive-change",
        "archive-replace",
    ] {
        let root = tempfile::tempdir().unwrap();
        let selection = network_profiles::development(
            &InstalledNetworkProfiles::from_installation_bytes(&image("fixture")).unwrap(),
        )
        .unwrap();
        let result = super::tests::bundle_fixture(root.path(), true, Some(selection));
        let profile = NativeBundleLayout::current().profiles_path(&result.bundle_root);
        let archive = result.archive_path.as_ref().unwrap();
        match mutation {
            "profile-change" => std::fs::write(&profile, image("changed")).unwrap(),
            "profile-missing" => std::fs::remove_file(&profile).unwrap(),
            "archive-change" => std::fs::write(archive, b"substituted archive").unwrap(),
            "archive-replace" => {
                let bytes = std::fs::read(archive).unwrap();
                std::fs::rename(archive, result.output_root.join("original-archive")).unwrap();
                std::fs::write(archive, bytes).unwrap();
            }
            _ => unreachable!(),
        }
        let absent = result.output_root.join("absent-stage");
        assert!(super::stage_bundle(&result, &absent).is_err());
        assert!(!absent.exists());
        let matrix = result.output_root.join("matrix.json");
        assert!(super::update_bundle_matrix(&result, &matrix, true).is_err());
        assert!(!matrix.exists());
        assert!(super::run_bundle_smoke(&result).is_err());
    }
}
