//! Local publication and clock-token adversarial tests; these do not qualify native proofs.

use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};

use super::super::tests::{MemoryArchive, fixture};
use super::*;

fn key(name: &str) -> SigningKey {
    let vectors: norito::json::Value = norito::json::from_str(include_str!(
        "../../../../../fixtures/kagemusha/wallet_v1_vectors.json"
    ))
    .unwrap();
    let row = vectors["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"].as_str() == Some(name))
        .unwrap();
    SigningKey::from_slice(&hex::decode(row["scalar_hex"].as_str().unwrap()).unwrap()).unwrap()
}

fn signature(key: &SigningKey, message: &[u8]) -> KagemushaDeviceSignatureV1 {
    let signature: Signature = key.sign(message);
    KagemushaDeviceSignatureV1::from_raw_bytes(
        &signature.normalize_s().unwrap_or(signature).to_bytes(),
    )
    .unwrap()
}

fn request() -> KagemushaWalletRequestV1 {
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
    let KagemushaWalletMessageV1::Request { mut request } = envelope.message else {
        panic!("Request fixture")
    };
    request.body.receiver_blacklist_version = 0;
    request.body.receiver_blacklist_root = [0; 32];
    request.signature = signature(&key("receiver_payment"), &request.body.signing_message());
    request.validate().unwrap();
    request
}

#[test]
fn exact_requests_keep_their_original_gap_and_survive_reopening() {
    let mut store = MemoryArchive::new();
    let mut request = request();
    let empty = IndexRoot::default();
    let off = retain_request(&mut store, empty, &request, None).unwrap();
    assert_eq!(
        off,
        retain_request(&mut store, off, &request, None).unwrap()
    );
    assert!(
        empty
            .get(&mut store, &request.request_digest())
            .unwrap()
            .is_none()
    );
    let value = off
        .get(&mut store, &request.request_digest())
        .unwrap()
        .unwrap();
    let record: IssuedRequestCustodyV1 = archive::decode(&value).unwrap();
    assert!(record.gap.is_none());
    let (restored, original) = record
        .read(
            &mut store,
            &request.body.scheme_id,
            &request.body.receiver_wallet_id,
            &request.request_digest(),
        )
        .unwrap();
    assert_eq!(original, archive::encode(&request).unwrap());
    assert_eq!(restored, request);
    assert!(record.gap(&mut store, &restored).unwrap().is_none());
    assert!(matches!(
        record.read(
            &mut store,
            &[42; 32],
            &request.body.receiver_wallet_id,
            &request.request_digest()
        ),
        Err(Error::WitnessLost(_))
    ));
    assert!(matches!(
        record.read(
            &mut store,
            &request.body.scheme_id,
            &[42; 32],
            &request.request_digest()
        ),
        Err(Error::WitnessLost(_))
    ));
    assert!(matches!(
        record.read(
            &mut store,
            &request.body.scheme_id,
            &request.body.receiver_wallet_id,
            &[42; 32]
        ),
        Err(Error::WitnessLost(_))
    ));
    let mut reopened = store.clone();
    assert_eq!(
        reopened
            .read_object(&record.request, KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1)
            .unwrap(),
        archive::encode(&request).unwrap()
    );

    let list: KagemushaWalletBlacklistV1 = fixture("KagemushaWalletBlacklistV1");
    let gap = list
        .gap_opening(&request.body.payer_account_digest)
        .unwrap();
    request.body.receiver_blacklist_version = list.body.list_version;
    request.body.receiver_blacklist_root = list.body.entries_root;
    request.signature = signature(&key("receiver_payment"), &request.body.signing_message());
    assert!(retain_request(&mut store, off, &request, None).is_err());
    let on = retain_request(&mut store, off, &request, Some(&gap)).unwrap();
    let value = on
        .get(&mut store, &request.request_digest())
        .unwrap()
        .unwrap();
    let record: IssuedRequestCustodyV1 = archive::decode(&value).unwrap();
    assert_eq!(record.gap(&mut store, &request).unwrap(), Some(gap));
    assert_eq!(
        store
            .read_object(
                &record.gap.unwrap(),
                KAGEMUSHA_WALLET_BLACKLIST_GAP_OPENING_TRANSCRIPT_BYTES_V1
            )
            .unwrap(),
        gap.transcript()
    );
    assert!(
        off.get(&mut store, &request.request_digest())
            .unwrap()
            .is_none()
    );
    assert_eq!(
        on,
        retain_request(&mut store, on, &request, Some(&gap)).unwrap()
    );
    let mut corrupt = gap;
    corrupt.lower[0] ^= 1;
    assert!(retain_request(&mut store, on, &request, Some(&corrupt)).is_err());
    store.remove(ArchiveKey::Object(record.request)).unwrap();
    assert!(matches!(
        store.read_object(&record.request, KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1),
        Err(Error::WitnessLost(_))
    ));
}

fn clock_fixture() -> (
    KagemushaWalletSchemeV1,
    KagemushaWalletSignerCertificateV1,
    KagemushaWalletStateV1,
    KagemushaWalletTimeAnchorV1,
) {
    let scheme: KagemushaWalletSchemeV1 = fixture("KagemushaWalletSchemeV1");
    let mut certificate: KagemushaWalletSignerCertificateV1 =
        fixture("KagemushaWalletSignerCertificateV1");
    certificate.body.role = KagemushaWalletSignerRoleV1::TimeAnchor;
    certificate.body.key = KagemushaDevicePublicKeyV1::from_sec1_bytes(
        key("time_anchor")
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes(),
    )
    .unwrap();
    certificate.signature = signature(&key("scheme_root"), &certificate.body.signing_message());
    certificate.verify(&scheme).unwrap();
    let credential: KagemushaWalletCredentialV1 = fixture("KagemushaWalletCredentialV1");
    let mut state =
        KagemushaWalletStateV1::bootstrap(&credential, kagemusha_wallet_field_from_u128_v1(1))
            .unwrap();
    // The time-bound helper is tested independently of credential renewal/proof admission.
    state.core.time_anchor_max_response_ms = 5000;
    let mut anchor: KagemushaWalletTimeAnchorV1 = fixture("KagemushaWalletTimeAnchorV1");
    anchor.body.wallet_id = state.core.wallet_id;
    anchor.body.signer_certificate = certificate.certificate_digest();
    anchor.signature = signature(&key("time_anchor"), &anchor.body.signing_message());
    anchor.verify(&scheme, &certificate).unwrap();
    (scheme, certificate, state, anchor)
}

fn exchange(
    state: &KagemushaWalletStateV1,
    anchor: &KagemushaWalletTimeAnchorV1,
) -> DirectTimeExchangeV1 {
    DirectTimeExchangeV1 {
        scheme: state.core.scheme_id,
        wallet: state.core.wallet_id,
        nonce: anchor.body.nonce,
        sent: KagemushaWalletMonotonicReadingV1 {
            boot_id: [9; 32],
            monotonic_ms: 1000,
        },
        maximum_response_ms: 5000,
    }
}

#[test]
fn direct_exchange_rejects_cached_foreign_late_and_rebooted_responses() {
    let (scheme, certificate, state, anchor) = clock_fixture();
    let received = KagemushaWalletMonotonicReadingV1 {
        boot_id: [9; 32],
        monotonic_ms: 6000,
    };
    assert_eq!(exchange(&state, &anchor).nonce(), anchor.body.nonce);
    let accepted = exchange(&state, &anchor)
        .complete(anchor, &certificate, &scheme, &state, received)
        .unwrap();
    assert_eq!(accepted.response_width_ms().unwrap(), 5000);
    for reading in [
        KagemushaWalletMonotonicReadingV1 {
            monotonic_ms: 6001,
            ..received
        },
        KagemushaWalletMonotonicReadingV1 {
            monotonic_ms: 999,
            ..received
        },
        KagemushaWalletMonotonicReadingV1 {
            boot_id: [8; 32],
            ..received
        },
    ] {
        assert!(
            exchange(&state, &anchor)
                .complete(anchor, &certificate, &scheme, &state, reading)
                .is_err()
        );
    }
    let mut token = exchange(&state, &anchor);
    token.nonce[0] ^= 1;
    assert!(
        token
            .complete(anchor, &certificate, &scheme, &state, received)
            .is_err()
    );
    let mut token = exchange(&state, &anchor);
    token.wallet[0] ^= 1;
    assert!(
        token
            .complete(anchor, &certificate, &scheme, &state, received)
            .is_err()
    );
    let mut tightened = state;
    tightened.core.time_anchor_max_response_ms = 4999;
    assert!(
        exchange(&state, &anchor)
            .complete(anchor, &certificate, &scheme, &tightened, received)
            .is_err()
    );
    let mut forged = anchor;
    forged.signature = signature(&key("payer_payment"), &anchor.body.signing_message());
    assert!(
        exchange(&state, &anchor)
            .complete(forged, &certificate, &scheme, &state, received)
            .is_err()
    );
}

#[test]
fn direct_anchor_index_is_exact_and_never_restarts_elapsed_time() {
    let (scheme, certificate, state, anchor) = clock_fixture();
    let anchored = exchange(&state, &anchor)
        .complete(
            anchor,
            &certificate,
            &scheme,
            &state,
            KagemushaWalletMonotonicReadingV1 {
                boot_id: [9; 32],
                monotonic_ms: 1100,
            },
        )
        .unwrap();
    let mut store = MemoryArchive::new();
    let empty = IndexRoot::default();
    let index = retain_anchor(&mut store, empty, &anchored).unwrap();
    assert_eq!(index, retain_anchor(&mut store, index, &anchored).unwrap());
    let mut shifted = anchored;
    shifted.request_monotonic_ms += 100;
    shifted.receive_monotonic_ms += 100;
    assert!(matches!(
        retain_anchor(&mut store, index, &shifted),
        Err(Error::WitnessLost(_))
    ));
    assert!(
        empty
            .get(&mut store, &anchor.time_anchor_digest())
            .unwrap()
            .is_none()
    );
    let address: [u8; 32] = index
        .get(&mut store, &anchor.time_anchor_digest())
        .unwrap()
        .unwrap()
        .try_into()
        .unwrap();
    let restored: KagemushaWalletAnchoredTimeV1 = archive::decode(
        &store
            .read_object(&address, ANCHOR_CUSTODY_MAX_BYTES)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(restored, anchored);
}
