//! Installation-selected trust and canonical native bundle custody regressions.

use super::*;
use iroha_crypto::{Algorithm, KeyPair};

fn profile(name: &str) -> InstalledNetworkProfile {
    InstalledNetworkProfile::new(
        name.into(),
        KeyPair::from_seed(vec![31; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
        7,
        "https://releases.example/checkpoint.nrt",
    )
    .unwrap()
}

#[test]
fn installed_profiles_require_explicit_canonical_authority_floor_and_https_location() {
    let valid = profile("fixture");
    assert_eq!(valid.network_name(), "fixture");
    assert_eq!(valid.release_trust().minimum_serial, 7);
    for url in [
        "http://releases.example/checkpoint.nrt",
        "https://RELEASES.example/checkpoint.nrt",
        "https://releases.example:443/checkpoint.nrt",
        "https://releases.example/a/../checkpoint.nrt",
        "https://user:secret@releases.example/checkpoint.nrt",
        "https://releases.example/checkpoint.nrt?key=attacker",
        "https://releases.example/checkpoint.nrt#fragment",
    ] {
        assert!(
            InstalledNetworkProfile::new("fixture".into(), valid.trust.public_key.clone(), 7, url)
                .is_err(),
            "{url}"
        );
    }
    for (name, floor) in [("Fixture", 1), ("fixture", 0), ("", 1)] {
        assert!(
            InstalledNetworkProfile::new(
                name.into(),
                valid.trust.public_key.clone(),
                floor,
                valid.checkpoint_url.as_str()
            )
            .is_err()
        );
    }
    assert!(
        InstalledNetworkProfile::new(
            "fixture".into(),
            KeyPair::from_seed(vec![31; 32], Algorithm::BlsNormal)
                .public_key()
                .clone(),
            1,
            valid.checkpoint_url.as_str()
        )
        .is_err()
    );
    let absent = InstalledNetworkProfiles::new(vec![]).unwrap();
    assert!(absent.select("taira").is_err());
    assert!(
        InstalledNetworkProfiles::from_installation_bytes(&absent.encode_installation().unwrap())
            .unwrap()
            .select("taira")
            .is_err()
    );
}

#[test]
fn installed_profile_set_roundtrips_sorted_and_loads_from_retained_custody() {
    let profiles =
        InstalledNetworkProfiles::new(vec![profile("second"), profile("first")]).unwrap();
    let bytes = profiles.encode_installation().unwrap();
    let decoded = InstalledNetworkProfiles::from_installation_bytes(&bytes).unwrap();
    assert_eq!(decoded.names().collect::<Vec<_>>(), ["first", "second"]);
    assert_eq!(
        decoded
            .select("first")
            .unwrap()
            .release_trust()
            .minimum_serial,
        7
    );
    assert!(decoded.select("FIRST").is_err());
    assert_eq!(decoded.encode_installation().unwrap(), bytes);
    let temporary = tempfile::tempdir().unwrap();
    let directory =
        iroha_fs::PrivateDirectory::open_or_create(temporary.path().join("installation")).unwrap();
    directory
        .write_atomic(
            NETWORK_PROFILES_FILENAME,
            &bytes,
            iroha_fs::PublishMode::CreateNew,
        )
        .unwrap();
    assert_eq!(
        InstalledNetworkProfiles::load(&directory.path().join(NETWORK_PROFILES_FILENAME))
            .unwrap()
            .encode_installation()
            .unwrap(),
        bytes
    );
    assert!(InstalledNetworkProfiles::load(&directory.path().join("missing.nrt")).is_err());
}

#[test]
fn installed_profile_decoder_rejects_duplicate_unsorted_oversized_or_trailing_records() {
    assert!(InstalledNetworkProfiles::new(vec![profile("same"), profile("same")]).is_err());
    assert!(
        InstalledNetworkProfiles::new(
            (0..=MAX_INSTALLED_NETWORK_PROFILES)
                .map(|i| profile(&format!("network-{i}")))
                .collect()
        )
        .is_err()
    );
    for names in [["second", "first"], ["same", "same"]] {
        let records = ProfileRecords {
            profiles: names.iter().map(|name| profile(name).record()).collect(),
        };
        assert!(
            InstalledNetworkProfiles::from_installation_bytes(
                &norito::encode_canonical(&records).unwrap()
            )
            .is_err()
        );
    }
    let mut bytes = InstalledNetworkProfiles::new(vec![profile("fixture")])
        .unwrap()
        .encode_installation()
        .unwrap();
    bytes.push(0);
    assert!(InstalledNetworkProfiles::from_installation_bytes(&bytes).is_err());
    assert!(InstalledNetworkProfiles::from_installation_bytes(&[]).is_err());
    assert!(
        InstalledNetworkProfiles::from_installation_bytes(&vec![
            0;
            MAX_INSTALLED_PROFILE_BYTES + 1
        ])
        .is_err()
    );
}
