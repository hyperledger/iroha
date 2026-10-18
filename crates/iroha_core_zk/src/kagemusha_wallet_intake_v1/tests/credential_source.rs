//! Current-credential binding at the actual intake branch, without a mock verifier.
//!
//! Signed credentials and the state/statement projections exercise this pure binding
//! check only. No Selected marker, valid monetary proof or admitted wallet is fabricated;
//! the installed renewal/reopen regression exercises those surrounding boundaries.

use p256::ecdsa::{Signature as P256Signature, SigningKey, signature::Signer as _};

use super::*;

struct Originals {
    scheme: KagemushaWalletSchemeV1,
    credential: KagemushaWalletCredentialV1,
    issuer: KagemushaWalletSignerCertificateV1,
    signing: SigningKey,
    state: KagemushaWalletStateV1,
    statement: KagemushaWalletStatementV1,
}

fn originals() -> Originals {
    let vectors: norito::json::Value = norito::json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/kagemusha/wallet_v1_vectors.json"
    )))
    .unwrap();
    let object = |name: &str| {
        let row = vectors["objects"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["type"].as_str() == Some(name))
            .unwrap();
        hex::decode(row["canonical_hex"].as_str().unwrap()).unwrap()
    };
    let request = vectors["envelopes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["kind"].as_str() == Some("Request"))
        .unwrap();
    let envelope: KagemushaWalletEnvelopeV1 =
        norito::decode_canonical(&hex::decode(request["canonical_hex"].as_str().unwrap()).unwrap())
            .unwrap();
    let KagemushaWalletMessageV1::Request { request } = envelope.message else {
        panic!("Request vector required")
    };
    let scheme: KagemushaWalletSchemeV1 =
        norito::decode_canonical(&object("KagemushaWalletSchemeV1")).unwrap();
    let credential = request.receiver_credential;
    let issuer = *request
        .certificates
        .certificate(
            &credential.body.issuer_certificate,
            KagemushaWalletSignerRoleV1::Enrollment,
        )
        .unwrap();
    credential.verify(&scheme, &issuer).unwrap();
    assert_eq!(credential.body.renewal_sequence, 0);
    let key = vectors["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"].as_str() == Some("receiver_issuer"))
        .unwrap();
    let signing =
        SigningKey::from_slice(&hex::decode(key["scalar_hex"].as_str().unwrap()).unwrap()).unwrap();
    let capsule: KagemushaWalletRecoveryCapsuleV1 =
        norito::decode_canonical(&object("KagemushaWalletRecoveryCapsuleV1")).unwrap();
    let state = capsule.body().successor_state;
    let statement = capsule.body().statement;
    state.validate_for_credential(&credential).unwrap();
    statement.validate_for_credential(&credential).unwrap();
    Originals {
        scheme,
        credential,
        issuer,
        signing,
        state,
        statement,
    }
}

fn renewal(
    originals: &Originals,
    previous: &KagemushaWalletCredentialV1,
) -> KagemushaWalletCredentialV1 {
    let mut body = previous.body;
    body.renewal_sequence += 1;
    body.issued_at_ms += 1;
    body.fresh_evidence.time_ms = body.issued_at_ms;
    if body.lease_expires_at_ms != 0 {
        body.lease_expires_at_ms += 1;
    }
    let signature: P256Signature = originals.signing.sign(&body.signing_message());
    let value = KagemushaWalletCredentialV1::sign(
        body,
        &originals.issuer,
        KagemushaWalletSignerOutputV1::Raw(signature.to_bytes().into()),
    )
    .unwrap();
    value.verify(&originals.scheme, &originals.issuer).unwrap();
    value.validate_replacement_of(previous).unwrap();
    value
}

#[test]
fn enrollment_without_selected_capsule_requires_exact_credential_zero() {
    let data = originals();
    let bytes = data.credential.to_canonical_bytes().unwrap();
    bind_source_credential(&data.credential, &bytes, None, || Ok(Some(bytes.clone()))).unwrap();
    for retained in [None, Some(vec![1, 2, 3])] {
        assert!(matches!(
            bind_source_credential(&data.credential, &bytes, None, || Ok(retained)),
            Err(Error::Authority("retained enrollment/credential original"))
        ));
    }
    let error = KagemushaWalletProviderErrorV1::UnavailableCustodyData {
        object: "credential",
    };
    assert!(matches!(
        bind_source_credential(&data.credential, &bytes, None, || Err(error)),
        Err(Error::Provider(actual)) if actual == error
    ));
    let renewed = renewal(&data, &data.credential);
    assert!(matches!(
        bind_source_credential(
            &renewed,
            &renewed.to_canonical_bytes().unwrap(),
            None,
            || { panic!("a renewal cannot use enrollment as a source") }
        ),
        Err(Error::Authority("renewal without selected source"))
    ));
}

#[test]
fn selected_source_accepts_exact_renewals_without_an_indexed_publication() {
    let data = originals();
    let mut previous = data.credential;
    for sequence in 1..=2 {
        let current = renewal(&data, &previous);
        assert_eq!(current.body.renewal_sequence, sequence);
        let mut state = data.state;
        state.core.credential_digest = current.credential_digest();
        state.core.lease_expires_at_ms = current.body.lease_expires_at_ms;
        let mut statement = data.statement;
        statement.credential_digest = current.credential_digest();
        // Both Pending and Released use this same selected-capsule binding. E6 is
        // not a second current-credential registry, even when it is unavailable.
        bind_source_credential(
            &current,
            &current.to_canonical_bytes().unwrap(),
            Some((&state, &statement)),
            || panic!("selected source must not read an indexed credential"),
        )
        .unwrap();
        for unselected in [data.credential, previous, renewal(&data, &current)] {
            assert!(matches!(
                bind_source_credential(
                    &unselected,
                    &unselected.to_canonical_bytes().unwrap(),
                    Some((&state, &statement)),
                    || panic!("stale or unselected credential cannot fall back to E6"),
                ),
                Err(Error::Authority("source credential/state"))
            ));
        }
        previous = current;
    }
}

#[test]
fn selected_source_requires_both_state_and_statement_credential_bindings() {
    let data = originals();
    let current = renewal(&data, &data.credential);
    let bytes = current.to_canonical_bytes().unwrap();
    let mut state = data.state;
    state.core.credential_digest = current.credential_digest();
    state.core.lease_expires_at_ms = current.body.lease_expires_at_ms;
    assert!(matches!(
        bind_source_credential(&current, &bytes, Some((&state, &data.statement)), || {
            panic!("selected statement mismatch cannot fall back to E6")
        }),
        Err(Error::Authority("source credential/statement"))
    ));
    let mut statement = data.statement;
    statement.credential_digest = current.credential_digest();
    assert!(matches!(
        bind_source_credential(&current, &bytes, Some((&data.state, &statement)), || {
            panic!("selected state mismatch cannot fall back to E6")
        }),
        Err(Error::Authority("source credential/state"))
    ));
}
