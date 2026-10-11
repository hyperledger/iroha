//! Retained source custody tests use authentic G1 fixtures, not proof qualification.

use super::super::tests::{MemoryArchive, enrollment_issuer, fixture};
use super::*;
use KagemushaWalletOperationKindV1 as K;
use KagemushaWalletPolicyUpdateKindV1 as U;
use PreparationOriginalV1 as R;

mod epoch_reader;

fn setup() -> (MemoryArchive, KagemushaWalletStateV1, SourceCustodyV1) {
    let credential: KagemushaWalletCredentialV1 = fixture("KagemushaWalletCredentialV1");
    let certificate = enrollment_issuer(&credential);
    let certificates = KagemushaWalletCertificateSetV1::new(vec![certificate]).unwrap();
    let state =
        KagemushaWalletStateV1::bootstrap(&credential, kagemusha_wallet_field_from_u128_v1(8))
            .unwrap();
    let mut store = MemoryArchive::new();
    let source = SourceCustodyV1::bootstrap(
        &mut store,
        &state,
        &credential.to_canonical_bytes().unwrap(),
        &archive::encode(&certificates).unwrap(),
    )
    .unwrap();
    (store, state, source)
}

fn view<'a>(
    store: &'a mut MemoryArchive,
    state: &KagemushaWalletStateV1,
    source: &SourceCustodyV1,
) -> PreparationCustodyV1<'a> {
    PreparationCustodyV1::new(
        store,
        source,
        state,
        K::Send,
        None,
        IndexRoot::default(),
        IndexRoot::default(),
        IndexRoot::default(),
    )
    .unwrap()
}

#[test]
fn selected_originals_are_bound_and_roundtrip_without_invented_absence() {
    let (mut store, state, source) = setup();
    let bytes = archive::encode(&source).unwrap();
    let decoded: SourceCustodyV1 = archive::decode(&bytes).unwrap();
    let mut custody = view(&mut store, &state, &decoded);
    assert!(custody.original(R::CurrentCredential).unwrap().is_some());
    assert!(
        custody
            .original(R::EnrollmentCertificates)
            .unwrap()
            .is_some()
    );
    for role in [R::SchemePolicy, R::Blacklist, R::QuotaShare, R::TimeAnchor] {
        assert!(custody.original(role).unwrap().is_none());
    }
    assert!(custody.anchored_time().unwrap().is_none());
    let restored = custody.finish(&state).unwrap();
    assert_eq!(archive::encode(&restored).unwrap(), bytes);
    let mut missing = source.clone();
    missing.originals[R::CurrentCredential.index()] = None;
    assert!(matches!(
        missing.require(&mut store, &state),
        Err(Error::WitnessLost(_))
    ));
    let mut malformed = source.clone();
    malformed.version = 2;
    assert!(malformed.require(&mut store, &state).is_err());
    let mut changed = state;
    changed.core.credential_digest = kagemusha_wallet_field_from_u128_v1(9);
    assert!(source.require(&mut store, &changed).is_err());
    store
        .remove(ArchiveKey::Object(source.originals[0].unwrap()))
        .unwrap();
    assert!(matches!(
        source.require(&mut store, &state),
        Err(Error::WitnessLost(_))
    ));
}

#[test]
fn refresh_original_drafts_are_role_bound_and_only_published_with_the_successor() {
    let (mut store, state, source) = setup();
    let policy: KagemushaWalletSchemePolicyV1 = fixture("KagemushaWalletSchemePolicyV1");
    let bytes = policy.to_canonical_bytes().unwrap();
    let mut send = view(&mut store, &state, &source);
    assert!(
        send.retain_successor_original(R::SchemePolicy, &bytes)
            .is_err()
    );
    drop(send);
    let mut refresh = PreparationCustodyV1::new(
        &mut store,
        &source,
        &state,
        K::RefreshPolicy,
        Some(U::SchemePolicy),
        IndexRoot::default(),
        IndexRoot::default(),
        IndexRoot::default(),
    )
    .unwrap();
    refresh
        .retain_successor_original(R::SchemePolicy, &bytes)
        .unwrap();
    refresh
        .retain_successor_original(R::SchemePolicy, &bytes)
        .unwrap();
    assert!(refresh.original(R::SchemePolicy).unwrap().is_none());
    assert!(
        refresh
            .retain_successor_original(R::Blacklist, &bytes)
            .is_err()
    );
    assert!(refresh.finish(&state).is_err());
    source.require(&mut store, &state).unwrap();
    let mut refresh = PreparationCustodyV1::new(
        &mut store,
        &source,
        &state,
        K::RefreshPolicy,
        Some(U::SchemePolicy),
        IndexRoot::default(),
        IndexRoot::default(),
        IndexRoot::default(),
    )
    .unwrap();
    refresh
        .retain_successor_original(R::SchemePolicy, &bytes)
        .unwrap();
    let mut next = state;
    next.rest.scheme_policy = policy.scheme_policy_digest();
    next.core.policy_epoch = policy.body.policy_epoch;
    let updated = refresh.finish(&next).unwrap();
    let mut restored = view(&mut store, &next, &updated);
    assert_eq!(restored.original(R::SchemePolicy).unwrap(), Some(bytes));
}

#[test]
fn signed_time_original_cannot_manufacture_direct_clock_custody() {
    let (mut store, mut state, mut source) = setup();
    let mut anchored: KagemushaWalletAnchoredTimeV1 = fixture("KagemushaWalletAnchoredTimeV1");
    anchored.receive_monotonic_ms = anchored.request_monotonic_ms;
    let anchor = anchored.anchor.to_canonical_bytes().unwrap();
    source.originals[R::TimeAnchor.index()] = Some(
        store
            .write_object(&anchor, R::TimeAnchor.maximum())
            .unwrap(),
    );
    state.rest.time_anchor = anchored.anchor.time_anchor_digest();
    let mut custody = view(&mut store, &state, &source);
    assert!(custody.original(R::TimeAnchor).unwrap().is_some());
    assert!(matches!(
        custody.anchored_time(),
        Err(Error::WitnessLost(_))
    ));
    drop(custody);
    let address = store
        .write_object(
            &archive::encode(&anchored).unwrap(),
            KAGEMUSHA_WALLET_TIME_ANCHOR_MAX_BYTES_V1 + 1024,
        )
        .unwrap();
    let anchors = IndexRoot::default()
        .set(&mut store, state.rest.time_anchor, &address)
        .unwrap();
    let mut custody = PreparationCustodyV1::new(
        &mut store,
        &source,
        &state,
        K::Send,
        None,
        IndexRoot::default(),
        anchors,
        IndexRoot::default(),
    )
    .unwrap();
    assert_eq!(custody.anchored_time().unwrap(), Some(anchored));
}

#[test]
fn issued_request_is_exact_local_custody_and_missing_gap_is_not_a_fallback() {
    let vectors: norito::json::Value = norito::json::from_str(include_str!(
        "../../../../../fixtures/kagemusha/wallet_v1_vectors.json"
    ))
    .unwrap();
    let row = vectors["envelopes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["variant"].as_str() == Some("Request"))
        .unwrap();
    let envelope: KagemushaWalletEnvelopeV1 =
        archive::decode(&hex::decode(row["canonical_hex"].as_str().unwrap()).unwrap()).unwrap();
    let KagemushaWalletMessageV1::Request { request } = envelope.message else {
        panic!("Request fixture")
    };
    let state = KagemushaWalletStateV1::bootstrap(
        &request.receiver_credential,
        kagemusha_wallet_field_from_u128_v1(10),
    )
    .unwrap();
    let mut store = MemoryArchive::new();
    let source = SourceCustodyV1::bootstrap(
        &mut store,
        &state,
        &request.receiver_credential.to_canonical_bytes().unwrap(),
        &archive::encode(&request.certificates).unwrap(),
    )
    .unwrap();
    let original = archive::encode(&request).unwrap();
    let key = request.request_digest();
    let record = IssuedRequestCustodyV1 {
        request: store
            .write_object(&original, KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1)
            .unwrap(),
        gap: None,
    };
    let issued = IndexRoot::default()
        .set(&mut store, key, &archive::encode(&record).unwrap())
        .unwrap();
    let mut custody = PreparationCustodyV1::new(
        &mut store,
        &source,
        &state,
        K::Receive,
        None,
        issued,
        IndexRoot::default(),
        IndexRoot::default(),
    )
    .unwrap();
    assert!(matches!(
        custody.issued_request(&[42; 32]),
        Err(Error::WitnessLost(_))
    ));
    if request.body.receiver_blacklist_version == 0 {
        assert_eq!(custody.issued_request(&key).unwrap(), original);
        assert!(custody.issued_request_gap(&key).unwrap().is_none());
    } else {
        assert!(matches!(
            custody.issued_request(&key),
            Err(Error::WitnessLost(_))
        ));
    }
}

#[test]
fn unavailable_original_storage_is_never_absence_or_missing_witness() {
    struct Unavailable;
    impl ObjectStore for Unavailable {
        fn read_object(&mut self, _: &[u8; 32], _: usize) -> Result<Vec<u8>, Error> {
            Err(Error::Storage(std::io::Error::other("unavailable")))
        }
        fn write_object(&mut self, _: &[u8], _: usize) -> Result<[u8; 32], Error> {
            Err(Error::Storage(std::io::Error::other("unavailable")))
        }
    }
    let (_, state, source) = setup();
    assert!(matches!(
        source.require(&mut Unavailable, &state),
        Err(Error::Storage(_))
    ));
    assert!(matches!(
        SourceCustodyV1::bootstrap(&mut Unavailable, &state, &[0], &[0]),
        Err(Error::Invalid(_)) | Err(Error::WitnessLost(_))
    ));
}

fn blacklist_successor(
    state: KagemushaWalletStateV1,
    list: &KagemushaWalletBlacklistV1,
) -> KagemushaWalletStateV1 {
    // Source-store descriptor probes only. No ReleasedStep, Advance receipt, proof or
    // financial acceptance is constructed by these tests.
    let mut next = state;
    next.rest.blacklist = list.blacklist_digest();
    next.core.blacklist_version = list.body.list_version;
    next.core.blacklist_root = list.body.entries_root;
    next.core.blacklist_issued_at_ms = list.body.issued_at_ms;
    next.validate().unwrap();
    next
}

fn retain_blacklist(
    store: &mut dyn ObjectStore,
    state: &KagemushaWalletStateV1,
    source: &SourceCustodyV1,
    list: &KagemushaWalletBlacklistV1,
) -> SourceCustodyV1 {
    let original = list.to_canonical_bytes().unwrap();
    let mut draft = PreparationCustodyV1::new(
        store,
        source,
        state,
        K::RefreshPolicy,
        Some(U::Blacklist),
        IndexRoot::default(),
        IndexRoot::default(),
        IndexRoot::default(),
    )
    .unwrap();
    draft
        .retain_successor_original(R::Blacklist, &original)
        .unwrap();
    draft
        .retain_successor_original(R::Blacklist, &original)
        .unwrap();
    assert!(draft.original(R::Blacklist).unwrap().is_none());
    let reference = draft.blacklist_reference.as_ref().unwrap();
    assert_eq!(
        draft.originals[R::Blacklist.index()],
        Some(reference.object_key())
    );
    assert_eq!(
        reference.to_canonical_bytes().unwrap(),
        BlacklistOriginalReferenceV1::for_original(&state.core.scheme_id, &original)
            .unwrap()
            .to_canonical_bytes()
            .unwrap()
    );
    draft.finish(&blacklist_successor(*state, list)).unwrap()
}

#[test]
fn selected_blacklist_reference_survives_source_restart_and_keeps_exact_original() {
    let (mut store, state, source) = setup();
    let list: KagemushaWalletBlacklistV1 = fixture("KagemushaWalletBlacklistV1");
    let original = list.to_canonical_bytes().unwrap();
    let selected = retain_blacklist(&mut store, &state, &source, &list);
    let next = blacklist_successor(state, &list);
    let frame = archive::encode(&selected).unwrap();
    assert!(frame.len() < SOURCE_CUSTODY_MAX_BYTES);
    let restored: SourceCustodyV1 = archive::decode(&frame).unwrap();
    restored.require(&mut store, &next).unwrap();
    assert_eq!(
        restored.original(&mut store, &next, R::Blacklist).unwrap(),
        Some(original.clone())
    );
    let retained = restored
        .blacklist_reference
        .as_ref()
        .unwrap()
        .to_canonical_bytes()
        .unwrap();
    super::super::verify_policy_update_original(
        U::Blacklist,
        &next.core.scheme_id,
        &retained,
        &original,
    )
    .unwrap();
    assert!(
        super::super::verify_policy_update_original(
            U::Blacklist,
            &next.core.scheme_id,
            &original,
            &original
        )
        .is_err()
    );
    assert_eq!(archive::encode(&restored).unwrap(), frame);
    source.require(&mut store, &state).unwrap();
}

#[test]
fn selected_blacklist_requires_reference_existing_cas_address_and_exact_state_header() {
    let (mut store, state, source) = setup();
    let list: KagemushaWalletBlacklistV1 = fixture("KagemushaWalletBlacklistV1");
    let selected = retain_blacklist(&mut store, &state, &source, &list);
    let next = blacklist_successor(state, &list);
    for fault in 0..4 {
        let mut changed = selected.clone();
        match fault {
            0 => changed.blacklist_reference = None,
            1 => changed.originals[R::Blacklist.index()] = None,
            2 => {
                changed.originals[R::Blacklist.index()] =
                    changed.originals[R::CurrentCredential.index()]
            }
            _ => changed.originals[R::Blacklist.index()] = Some([0; 32]),
        }
        assert!(matches!(
            changed.require(&mut store, &next),
            Err(Error::WitnessLost(_))
        ));
    }
    let mut unheld = source.clone();
    unheld.blacklist_reference = selected.blacklist_reference.clone();
    assert!(matches!(
        unheld.original(&mut store, &state, R::Blacklist),
        Err(Error::WitnessLost(_))
    ));
    for fault in 0..3 {
        let mut changed = next;
        match fault {
            0 => changed.core.blacklist_version += 1,
            1 => changed.core.blacklist_root = kagemusha_wallet_field_from_u128_v1(77),
            _ => changed.core.blacklist_issued_at_ms += 1,
        }
        changed.validate().unwrap();
        assert!(matches!(
            selected.require(&mut store, &changed),
            Err(Error::WitnessLost("selected blacklist state header"))
        ));
    }
    selected.require(&mut store, &next).unwrap();
}

#[derive(Clone, Copy)]
enum BlacklistFault {
    Missing,
    Short,
    Extra,
    Corrupt,
    Unavailable,
    Protected,
    WriteBefore,
    WriteAfter,
    WrongKey,
}

struct BlacklistStoreProbe {
    inner: MemoryArchive,
    key: [u8; 32],
    fault: BlacklistFault,
    exact_bound: usize,
    reads: usize,
}

impl ObjectStore for BlacklistStoreProbe {
    fn read_object(&mut self, key: &[u8; 32], maximum: usize) -> Result<Vec<u8>, Error> {
        if *key != self.key {
            return self.inner.read_object(key, maximum);
        }
        self.reads += 1;
        assert_eq!(
            maximum, self.exact_bound,
            "selected extent is the allocation/read bound"
        );
        match self.fault {
            BlacklistFault::Missing => Err(Error::WitnessLost("probe missing selected blacklist")),
            BlacklistFault::Unavailable => Err(Error::Storage(std::io::Error::from(
                std::io::ErrorKind::WouldBlock,
            ))),
            BlacklistFault::Protected => Err(Error::Provider(
                crate::kagemusha_wallet_advance_v1::KagemushaWalletProviderErrorV1::Unavailable(
                    crate::kagemusha_wallet_advance_v1::KagemushaWalletUnavailableV1::Locked,
                ),
            )),
            fault => {
                let mut bytes = self.inner.read_object(key, maximum)?;
                match fault {
                    BlacklistFault::Short => {
                        bytes.pop();
                    }
                    BlacklistFault::Extra => bytes.push(0),
                    BlacklistFault::Corrupt => {
                        let last = bytes.len() - 1;
                        bytes[last] ^= 1;
                    }
                    _ => {}
                }
                Ok(bytes)
            }
        }
    }
    fn write_object(&mut self, bytes: &[u8], maximum: usize) -> Result<[u8; 32], Error> {
        let target =
            crate::kagemusha_wallet_advance_v1::kagemusha_wallet_archive_object_digest_v1(bytes)
                == self.key;
        if target && matches!(self.fault, BlacklistFault::WriteBefore) {
            return Err(Error::Storage(std::io::Error::from(
                std::io::ErrorKind::WouldBlock,
            )));
        }
        let address = self.inner.write_object(bytes, maximum)?;
        if target {
            if matches!(self.fault, BlacklistFault::WriteAfter) {
                return Err(Error::Storage(std::io::Error::from(
                    std::io::ErrorKind::WouldBlock,
                )));
            }
            if matches!(self.fault, BlacklistFault::WrongKey) {
                return Ok([0x91; 32]);
            }
        }
        Ok(address)
    }
}

#[test]
fn blacklist_partial_publication_and_bad_readback_cannot_update_the_source_draft() {
    let list: KagemushaWalletBlacklistV1 = fixture("KagemushaWalletBlacklistV1");
    let original = list.to_canonical_bytes().unwrap();
    let key = BlacklistOriginalReferenceV1::for_original(&list.body.scheme_id, &original)
        .unwrap()
        .object_key();
    for fault in [
        BlacklistFault::Missing,
        BlacklistFault::Short,
        BlacklistFault::Extra,
        BlacklistFault::Corrupt,
        BlacklistFault::Unavailable,
        BlacklistFault::Protected,
        BlacklistFault::WriteBefore,
        BlacklistFault::WriteAfter,
        BlacklistFault::WrongKey,
    ] {
        let (inner, state, source) = setup();
        let mut store = BlacklistStoreProbe {
            inner,
            key,
            fault,
            exact_bound: original.len(),
            reads: 0,
        };
        let mut draft = PreparationCustodyV1::new(
            &mut store,
            &source,
            &state,
            K::RefreshPolicy,
            Some(U::Blacklist),
            IndexRoot::default(),
            IndexRoot::default(),
            IndexRoot::default(),
        )
        .unwrap();
        let before = archive::encode(&draft.snapshot()).unwrap();
        let error = draft
            .retain_successor_original(R::Blacklist, &original)
            .unwrap_err();
        match fault {
            BlacklistFault::Unavailable
            | BlacklistFault::WriteBefore
            | BlacklistFault::WriteAfter => assert!(matches!(error, Error::Storage(_))),
            BlacklistFault::Protected => assert!(matches!(error, Error::Provider(_))),
            _ => assert!(matches!(error, Error::WitnessLost(_))),
        }
        assert!(!draft.updated[R::Blacklist.index()]);
        assert!(draft.blacklist_reference.is_none());
        assert_eq!(archive::encode(&draft.snapshot()).unwrap(), before);
        assert!(draft.original(R::Blacklist).unwrap().is_none());
        drop(draft);
        source.require(&mut store, &state).unwrap();
    }
}

#[test]
fn selected_blacklist_storage_loss_corruption_and_unavailability_remain_distinct() {
    let list: KagemushaWalletBlacklistV1 = fixture("KagemushaWalletBlacklistV1");
    let original = list.to_canonical_bytes().unwrap();
    for fault in [
        BlacklistFault::Missing,
        BlacklistFault::Short,
        BlacklistFault::Extra,
        BlacklistFault::Corrupt,
        BlacklistFault::Unavailable,
        BlacklistFault::Protected,
    ] {
        let (mut inner, state, source) = setup();
        let selected = retain_blacklist(&mut inner, &state, &source, &list);
        let next = blacklist_successor(state, &list);
        let key = selected.blacklist_reference.as_ref().unwrap().object_key();
        let mut store = BlacklistStoreProbe {
            inner,
            key,
            fault,
            exact_bound: original.len(),
            reads: 0,
        };
        let error = selected
            .original(&mut store, &next, R::Blacklist)
            .unwrap_err();
        match fault {
            BlacklistFault::Unavailable => assert!(matches!(error, Error::Storage(_))),
            BlacklistFault::Protected => assert!(matches!(error, Error::Provider(_))),
            _ => assert!(matches!(error, Error::WitnessLost(_))),
        }
        assert_eq!(store.reads, 1);
    }
}

#[test]
fn genuine_signed_large_full_list_is_retained_only_by_bounded_reference() {
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};
    // The existing golden RegulatoryPolicy certificate and its actual fixture key
    // authenticate this storage vector. No issuer, Native verdict or step is fabricated.
    let vectors: norito::json::Value = norito::json::from_str(include_str!(
        "../../../../../fixtures/kagemusha/wallet_v1_vectors.json"
    ))
    .unwrap();
    let row = vectors["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"].as_str() == Some("regulator"))
        .unwrap();
    let signing =
        SigningKey::from_slice(&hex::decode(row["scalar_hex"].as_str().unwrap()).unwrap()).unwrap();
    let certificate: KagemushaWalletSignerCertificateV1 =
        fixture("KagemushaWalletSignerCertificateV1");
    let scheme: KagemushaWalletSchemeV1 = fixture("KagemushaWalletSchemeV1");
    let golden: KagemushaWalletBlacklistV1 = fixture("KagemushaWalletBlacklistV1");
    let entries: Vec<_> = (1..=8192)
        .map(|n| KagemushaWalletBlacklistEntryV1 {
            account_digest: kagemusha_wallet_field_from_u128_v1(n),
        })
        .collect();
    let mut body = golden.body;
    body.entry_count = entries.len() as u32;
    body.entries_root = kagemusha_wallet_blacklist_root_v1(&entries).unwrap();
    let signature: Signature = signing.sign(&body.signing_message());
    let list = KagemushaWalletBlacklistV1::sign(
        body,
        entries,
        &certificate,
        KagemushaWalletSignerOutputV1::Raw(signature.to_bytes().into()),
    )
    .unwrap();
    list.verify(&scheme, &certificate).unwrap();
    let original = list.to_canonical_bytes().unwrap();
    assert!(original.len() > 262_144);
    assert!(original.len() <= KAGEMUSHA_WALLET_BLACKLIST_MAX_BYTES_V1);
    let (mut store, state, source) = setup();
    let selected = retain_blacklist(&mut store, &state, &source, &list);
    let next = blacklist_successor(state, &list);
    let retained = selected
        .blacklist_reference
        .as_ref()
        .unwrap()
        .to_canonical_bytes()
        .unwrap();
    assert!(retained.len() <= 512);
    super::super::verify_policy_update_original(
        U::Blacklist,
        &scheme.scheme_id(),
        &retained,
        &original,
    )
    .unwrap();
    let descriptor = archive::encode(&selected).unwrap();
    assert!(descriptor.len() < SOURCE_CUSTODY_MAX_BYTES);
    let restored: SourceCustodyV1 = archive::decode(&descriptor).unwrap();
    assert_eq!(
        restored.original(&mut store, &next, R::Blacklist).unwrap(),
        Some(original)
    );
}
