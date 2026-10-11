//! Storage/issuer-source tests over existing signed golden originals. No released step,
//! monetary receipt, proof verdict or new issuer signature is manufactured here.

use super::*;
use crate::kagemusha_wallet_state_v1::{
    ArchiveKey,
    policy_custody::publish_blacklist_original,
    tests::{MemoryArchive, fixture},
};

fn inputs() -> (
    KagemushaWalletSchemeV1,
    KagemushaWalletStateV1,
    Vec<u8>,
    Vec<u8>,
) {
    let scheme: KagemushaWalletSchemeV1 = fixture("KagemushaWalletSchemeV1");
    let list: KagemushaWalletBlacklistV1 = fixture("KagemushaWalletBlacklistV1");
    let all: norito::json::Value = norito::json::from_str(include_str!(
        "../../../../../../fixtures/kagemusha/wallet_v1_vectors.json"
    ))
    .unwrap();
    let row = all["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| {
            row["type"].as_str() == Some("KagemushaWalletRecoveryCapsuleV1")
                && row["variant"].as_str() == Some("QuotaShare, 64 retained predecessor slots")
        })
        .unwrap();
    let capsule: KagemushaWalletRecoveryCapsuleV1 =
        archive::decode(&hex::decode(row["canonical_hex"].as_str().unwrap()).unwrap()).unwrap();
    let certificates = capsule
        .retained_inputs
        .iter()
        .find(|input| input.role == KagemushaWalletRetainedInputRoleV1::CertificateSet)
        .unwrap()
        .bytes
        .clone();
    let mut state = capsule.successor_state;
    // This local state projection exercises custody joins only; it is never released/proved.
    state.rest.blacklist = list.blacklist_digest();
    state.core.blacklist_version = list.body.list_version;
    state.core.blacklist_root = list.body.entries_root;
    state.core.blacklist_issued_at_ms = list.body.issued_at_ms;
    state.validate().unwrap();
    let full = list.to_canonical_bytes().unwrap();
    authenticate(&scheme, &state, &full, &certificates).unwrap();
    (scheme, state, full, certificates)
}

#[derive(Clone, Copy)]
enum Fault {
    None,
    Missing,
    Corrupt,
    Unavailable,
    Protected,
}
struct Probe {
    archive: MemoryArchive,
    selected: Option<[u8; 32]>,
    fault: Fault,
    reads: usize,
    writes: usize,
    fail_after: Option<usize>,
}
impl Probe {
    fn new() -> Self {
        Self {
            archive: MemoryArchive::new(),
            selected: None,
            fault: Fault::None,
            reads: 0,
            writes: 0,
            fail_after: None,
        }
    }
}
impl ArchiveStore for Probe {
    fn binding(&self) -> ([u8; 32], [u8; 32]) {
        self.archive.binding()
    }
    fn get(&mut self, key: ArchiveKey, maximum: usize) -> Result<Option<Vec<u8>>, Error> {
        self.reads += 1;
        if matches!(key, ArchiveKey::Object(digest) if Some(digest) == self.selected) {
            match self.fault {
                Fault::Missing => return Ok(None),
                Fault::Corrupt => {
                    let mut bytes = self.archive.get(key, maximum)?.unwrap();
                    let last = bytes.len() - 1;
                    bytes[last] ^= 1;
                    return Ok(Some(bytes));
                }
                Fault::Unavailable => {
                    return Err(Error::Storage(std::io::ErrorKind::WouldBlock.into()));
                }
                Fault::Protected => {
                    return Err(Error::Provider(ProviderError::Unavailable(
                        crate::kagemusha_wallet_advance_v1::KagemushaWalletUnavailableV1::Locked,
                    )));
                }
                Fault::None => {}
            }
        }
        self.archive.get(key, maximum)
    }
    fn put(&mut self, key: ArchiveKey, bytes: &[u8]) -> Result<(), Error> {
        self.writes += 1;
        self.archive.put(key, bytes)?;
        if self.fail_after == Some(self.writes) {
            return Err(Error::Storage(std::io::ErrorKind::WouldBlock.into()));
        }
        Ok(())
    }
    fn remove(&mut self, key: ArchiveKey) -> Result<(), Error> {
        self.archive.remove(key)
    }
}

#[test]
fn bounded_selected_index_restores_exact_full_and_certificate_originals_after_capsule_removal() {
    let (scheme, state, full, certificates) = inputs();
    let mut objects = Probe::new();
    let reference = publish_blacklist_original(&mut objects, &scheme.scheme_id(), &full).unwrap();
    let mut historical = IndexRoot::default();
    for n in 0..128u16 {
        let mut key = [0xa7; 32];
        key[..2].copy_from_slice(&n.to_be_bytes());
        historical = historical.set(&mut objects, key, &[1]).unwrap();
    }
    let selected = retain(
        &mut objects,
        historical,
        &scheme,
        &state,
        &reference,
        &certificates,
    )
    .unwrap();
    let bytes = selected
        .get(&mut objects, &state.rest.blacklist)
        .unwrap()
        .unwrap();
    assert!(bytes.len() <= index::INDEX_VALUE_LIMIT);
    let entry: BlacklistSourceEntryV1 = archive::decode(&bytes).unwrap();
    assert_eq!(entry.original, reference);
    assert_eq!(entry.certificates_digest, object_digest(&certificates));
    assert_eq!(entry.certificates_bytes as usize, certificates.len());
    assert_ne!(
        state.rest.blacklist,
        object_digest(&full),
        "signed policy digest and archive content hash are distinct selectors"
    );
    let capsule: KagemushaWalletRecoveryCapsuleV1 = fixture("KagemushaWalletRecoveryCapsuleV1");
    let capsule_bytes = capsule.to_canonical_bytes().unwrap();
    let capsule_key = ArchiveKey::Capsule(capsule.capsule_digest().unwrap());
    objects.put(capsule_key, &capsule_bytes).unwrap();
    objects.remove(capsule_key).unwrap();
    // Reopened archive capability over the same exact durable objects and selected root.
    let mut reopened = Probe {
        archive: objects.archive.clone(),
        ..Probe::new()
    };
    let before = reopened.reads;
    assert_eq!(
        selected_originals(&mut reopened, selected, &scheme, &state).unwrap(),
        Some((full.clone(), certificates.clone()))
    );
    assert!(
        reopened.reads - before <= 259,
        "one bounded Patricia path and exactly two originals"
    );
    assert_eq!(
        selected_originals(&mut reopened, IndexRoot::default(), &scheme, &state)
            .unwrap_err()
            .to_string(),
        Error::WitnessLost("selected blacklist source index").to_string()
    );
    assert_eq!(
        retain(
            &mut reopened,
            selected,
            &scheme,
            &state,
            &reference,
            &certificates
        )
        .unwrap(),
        selected
    );
}

#[test]
fn selected_list_certificates_and_index_loss_corruption_unavailability_never_mean_no_list() {
    let (scheme, state, full, certificates) = inputs();
    let mut objects = Probe::new();
    let reference = publish_blacklist_original(&mut objects, &scheme.scheme_id(), &full).unwrap();
    let selected = retain(
        &mut objects,
        IndexRoot::default(),
        &scheme,
        &state,
        &reference,
        &certificates,
    )
    .unwrap();
    for digest in [
        object_digest(&full),
        object_digest(&certificates),
        selected.0,
    ] {
        objects.selected = Some(digest);
        for fault in [
            Fault::Missing,
            Fault::Corrupt,
            Fault::Unavailable,
            Fault::Protected,
        ] {
            objects.fault = fault;
            let error = selected_originals(&mut objects, selected, &scheme, &state).unwrap_err();
            match fault {
                Fault::Missing | Fault::Corrupt => assert!(matches!(error, Error::WitnessLost(_))),
                Fault::Unavailable => assert!(matches!(error, Error::Storage(_))),
                Fault::Protected => assert!(matches!(error, Error::Provider(_))),
                Fault::None => unreachable!(),
            }
        }
    }
    objects.fault = Fault::None;
    assert_eq!(
        selected_originals(&mut objects, selected, &scheme, &state).unwrap(),
        Some((full, certificates))
    );
}

#[test]
fn exact_current_policy_join_and_certificate_entry_bounds_fail_closed() {
    let (scheme, state, full, certificates) = inputs();
    let mut objects = Probe::new();
    let reference = publish_blacklist_original(&mut objects, &scheme.scheme_id(), &full).unwrap();
    let selected = retain(
        &mut objects,
        IndexRoot::default(),
        &scheme,
        &state,
        &reference,
        &certificates,
    )
    .unwrap();
    for field in 0..4 {
        let mut changed = state.clone();
        match field {
            0 => changed.rest.blacklist[0] ^= 1,
            1 => changed.core.blacklist_version += 1,
            2 => changed.core.blacklist_root[0] ^= 1,
            3 => changed.core.blacklist_issued_at_ms += 1,
            _ => unreachable!(),
        }
        assert!(selected_originals(&mut objects, selected, &scheme, &changed).is_err());
    }
    let bytes = selected
        .get(&mut objects, &state.rest.blacklist)
        .unwrap()
        .unwrap();
    let entry: BlacklistSourceEntryV1 = archive::decode(&bytes).unwrap();
    for field in 0..4 {
        let mut changed = entry.clone();
        match field {
            0 => changed.version += 1,
            1 => changed.certificates_digest[0] ^= 1,
            2 => changed.certificates_bytes += 1,
            3 => changed.certificates_bytes = (KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1 + 1) as u32,
            _ => unreachable!(),
        }
        assert!(changed.read(&mut objects, &scheme, &state).is_err());
    }
    let foreign_scheme = KagemushaWalletSchemeV1 {
        version: 2,
        ..scheme.clone()
    };
    let before = objects.reads;
    assert!(entry.read(&mut objects, &foreign_scheme, &state).is_err());
    assert_eq!(
        before, objects.reads,
        "foreign source reference rejected before reading objects"
    );
    let empty_certificates = archive::encode(&KagemushaWalletCertificateSetV1::default()).unwrap();
    assert!(
        retain(
            &mut objects,
            selected,
            &scheme,
            &state,
            &reference,
            &empty_certificates
        )
        .is_err(),
        "authentic selected RegulatoryPolicy role is mandatory"
    );
}

#[test]
fn partial_certificate_or_index_publication_keeps_old_source_and_retry_reads_exact_originals() {
    let (scheme, state, full, certificates) = inputs();
    for fail in [1, 2] {
        let mut objects = Probe::new();
        let reference =
            publish_blacklist_original(&mut objects, &scheme.scheme_id(), &full).unwrap();
        let old = IndexRoot::default();
        objects.writes = 0;
        objects.fail_after = Some(fail);
        assert!(matches!(
            retain(
                &mut objects,
                old,
                &scheme,
                &state,
                &reference,
                &certificates
            ),
            Err(Error::Storage(_))
        ));
        assert!(
            old.get(&mut objects, &state.rest.blacklist)
                .unwrap()
                .is_none()
        );
        objects.fail_after = None;
        let selected = retain(
            &mut objects,
            old,
            &scheme,
            &state,
            &reference,
            &certificates,
        )
        .unwrap();
        assert_eq!(
            selected_originals(&mut objects, selected, &scheme, &state).unwrap(),
            Some((full.clone(), certificates.clone()))
        );
    }
}
