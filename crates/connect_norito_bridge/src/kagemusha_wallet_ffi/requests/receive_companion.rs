//! Bounded Payment and payer companion originals for the ordinary native Receive owner.
//!
//! This adapter grants no proof or monetary verdict. It retains Payment bytes exactly and
//! forwards the companion's payer credential and certificates to ordinary Receive admission.

use super::*;

fn decode<T>(bytes: &[u8]) -> Result<T>
where
    T: norito::NoritoSerialize,
    for<'de> T: norito::NoritoDeserialize<'de>,
{
    if bytes.is_empty() || bytes.len() > KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1 {
        return Err(Failure::code(INVALID));
    }
    norito::decode_canonical_with_limits(bytes, norito::canonical_decode_limits(bytes.len()))
        .map_err(|_| Failure::code(INVALID))
}

pub(super) fn action(
    payment_bytes: &[u8],
    companion_bytes: &[u8],
) -> Result<state::OperationActionV1> {
    let payment: KagemushaWalletPaymentV1 = decode(payment_bytes)?;
    let companion = KagemushaWalletPayerCompanionV1::decode_canonical(companion_bytes)
        .map_err(|_| Failure::code(INVALID))?;
    // Bind the unsigned companion to this Payment's Ω(pred) credential and Request payer before
    // deriving the carried originals. Scheme/root certification, permanent credit deduplication
    // and all A/proof predicates remain with Receive.
    companion
        .check_payment(&payment)
        .map_err(|_| Failure::code(INVALID))?;
    let credential = companion
        .payer_credential
        .to_canonical_bytes()
        .map_err(|_| Failure::code(INVALID))?;
    let certificates =
        norito::encode_canonical(&companion.certificates).map_err(|_| Failure::code(INVALID))?;
    if credential.len() > KAGEMUSHA_WALLET_CREDENTIAL_MAX_BYTES_V1
        || certificates.len() > KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1
    {
        return Err(Failure::code(INVALID));
    }
    Ok(state::OperationActionV1::Receive {
        payment: payment_bytes.to_vec(),
        payer_credential: credential,
        certificates,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vectors() -> norito::json::Value {
        // Frozen seeded DATA vectors include stand-in proofs. They confer no wallet authority.
        norito::json::from_str(include_str!(
            "../../../../../fixtures/kagemusha/wallet_v1_vectors.json"
        ))
        .unwrap()
    }

    fn original(name: &str) -> Vec<u8> {
        let fixture = vectors();
        let row = fixture["envelopes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["kind"].as_str() == Some(name))
            .unwrap();
        let frame = hex::decode(row["canonical_hex"].as_str().unwrap()).unwrap();
        let scheme = hex::decode(row["scheme_id_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let kind = u8::try_from(row["tag"].as_u64().unwrap()).unwrap();
        crate::kagemusha_wallet_ffi::transport::convert(kind, false, &frame, &scheme).unwrap()
    }

    // The vectored Receive capsule retains the exact payer credential and issuer set that its
    // Payment was received with: the companion the payer sends beside that Payment.
    fn companion() -> KagemushaWalletPayerCompanionV1 {
        let fixture = vectors();
        let row = fixture["objects"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["type"].as_str() == Some("KagemushaWalletRecoveryCapsuleV1"))
            .unwrap();
        let bytes = hex::decode(row["canonical_hex"].as_str().unwrap()).unwrap();
        let capsule: KagemushaWalletRecoveryCapsuleV1 = norito::decode_canonical_with_limits(
            &bytes,
            norito::canonical_decode_limits(bytes.len()),
        )
        .unwrap();
        assert_eq!(capsule.body().kind, KagemushaWalletOperationKindV1::Receive);
        let retained = |role| {
            capsule
                .body()
                .retained_inputs
                .iter()
                .find(|input| input.role == role)
                .unwrap()
                .bytes
                .clone()
        };
        let companion = KagemushaWalletPayerCompanionV1 {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            payer_credential: decode(&retained(KagemushaWalletRetainedInputRoleV1::Credential))
                .unwrap(),
            certificates: decode(&retained(
                KagemushaWalletRetainedInputRoleV1::CertificateSet,
            ))
            .unwrap(),
        };
        companion.validate().unwrap();
        companion
    }

    #[test]
    fn original_payment_and_companion_payer_are_preserved_without_proof_admission() {
        let payment = original("Payment");
        let companion = companion();
        let companion_bytes = companion.to_canonical_bytes().unwrap();
        assert!(companion_bytes.len() <= KAGEMUSHA_WALLET_PAYER_COMPANION_MAX_BYTES_V1);
        let admitted = action(&payment, &companion_bytes).unwrap();
        let state::OperationActionV1::Receive {
            payment: retained,
            payer_credential,
            certificates,
        } = &admitted
        else {
            panic!("Receive only")
        };
        assert_eq!(&payment, retained);
        assert_eq!(
            payer_credential,
            &companion.payer_credential.to_canonical_bytes().unwrap()
        );
        assert_eq!(
            certificates,
            &norito::encode_canonical(&companion.certificates).unwrap()
        );
        assert_eq!(action(&payment, &companion_bytes).unwrap(), admitted);
    }

    #[test]
    fn every_foreign_payer_binding_is_refused() {
        let payment: KagemushaWalletPaymentV1 = decode(&original("Payment")).unwrap();
        let companion = companion().to_canonical_bytes().unwrap();
        let request: KagemushaWalletRequestV1 = decode(&original("Request")).unwrap();
        for binding in 0..5 {
            let mut changed = payment.clone();
            match binding {
                0 => changed.send.statement.scheme_id[0] ^= 1,
                1 => {
                    if let KagemushaWalletLineageSlotV1::Present { lineage } =
                        &mut changed.send.lineage
                    {
                        lineage.public.wallet_id[0] ^= 1;
                    }
                }
                2 => changed.request.payer_account_digest[0] ^= 1,
                3 => {
                    if let KagemushaWalletLineageSlotV1::Present { lineage } =
                        &mut changed.send.lineage
                    {
                        lineage.public.credential_digest[0] ^= 1;
                    }
                }
                _ => {
                    if let KagemushaWalletLineageSlotV1::Present { lineage } =
                        &mut changed.send.lineage
                    {
                        lineage.public.payment_key = request.receiver_credential.body.payment_key;
                    }
                    assert_ne!(
                        changed.send.lineage.lineage().unwrap().public.payment_key,
                        payment.send.lineage.lineage().unwrap().public.payment_key
                    );
                }
            }
            assert_ne!(changed, payment, "binding {binding}");
            let bytes = norito::encode_canonical(&changed).unwrap();
            assert!(action(&bytes, &companion).is_err(), "binding {binding}");
        }
    }

    #[test]
    fn another_wallets_valid_companion_is_refused() {
        let payment = original("Payment");
        let request: KagemushaWalletRequestV1 = decode(&original("Request")).unwrap();
        // The receiver's own credential with exactly its issuer is a structurally valid
        // companion, but not the credential of this Payment's Ω(pred).
        let issuer = *request
            .certificates
            .certificate(
                &request.receiver_credential.body.issuer_certificate,
                KagemushaWalletSignerRoleV1::Enrollment,
            )
            .unwrap();
        let foreign =
            KagemushaWalletPayerCompanionV1::new(request.receiver_credential, &issuer).unwrap();
        assert!(action(&payment, &foreign.to_canonical_bytes().unwrap()).is_err());
    }

    #[test]
    fn malformed_trailing_oversized_and_unbound_originals_are_refused() {
        let payment = original("Payment");
        let companion = companion();
        let companion_bytes = companion.to_canonical_bytes().unwrap();
        for invalid in [vec![], vec![0], vec![0; 10_001]] {
            assert!(action(&invalid, &companion_bytes).is_err());
            assert!(action(&payment, &invalid).is_err());
        }
        let oversized = vec![0; KAGEMUSHA_WALLET_PAYER_COMPANION_MAX_BYTES_V1 + 1];
        assert!(action(&payment, &oversized).is_err());
        let mut trailing = payment.clone();
        trailing.push(0);
        assert!(action(&trailing, &companion_bytes).is_err());
        let mut trailing = companion_bytes;
        trailing.push(0);
        assert!(action(&payment, &trailing).is_err());
        // Another version, and certificate sets other than exactly the credential's issuer.
        let mut versioned = companion.clone();
        versioned.version += 1;
        assert!(action(&payment, &norito::encode_canonical(&versioned).unwrap()).is_err());
        let mut doubled = companion.clone();
        let issuer = doubled.certificates.certificates[0];
        doubled.certificates.certificates.push(issuer);
        assert!(action(&payment, &norito::encode_canonical(&doubled).unwrap()).is_err());
        let mut empty = companion;
        empty.certificates.certificates.clear();
        assert!(action(&payment, &norito::encode_canonical(&empty).unwrap()).is_err());
    }
}
