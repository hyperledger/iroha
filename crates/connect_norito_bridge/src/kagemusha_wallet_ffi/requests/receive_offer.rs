//! Bounded signed-Offer payer originals for the ordinary native Receive owner.
//!
//! This adapter grants no proof or monetary verdict. It retains Payment bytes exactly and
//! forwards the session's actual credential and certificates to ordinary Receive admission.

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

pub(super) fn action(payment_bytes: &[u8], offer_bytes: &[u8]) -> Result<state::OperationActionV1> {
    let offer: KagemushaWalletOfferV1 = decode(offer_bytes)?;
    let payment: KagemushaWalletPaymentV1 = decode(payment_bytes)?;
    // Authenticate the session signature before deriving the carried originals. Scheme/root
    // certification, permanent credit deduplication and all A/proof predicates remain with Receive.
    offer.validate().map_err(|_| Failure::code(INVALID))?;
    let requested = &payment.request.body;
    let payer = &offer.payer_credential.body;
    if offer.body.scheme_id != requested.scheme_id
        || offer.body.asset_digest != requested.asset_digest
        || offer.body.payer_wallet_id != requested.payer_wallet_id
        || payer.account_digest != requested.payer_account_digest
        || offer.body.next_send != requested.send_ordinal
        || offer.body.amount != requested.amount
        || offer.body.payer_credential_digest != payment.payer_credential_digest
        || payer.payment_key != payment.payer_payment_key
    {
        return Err(Failure::code(INVALID));
    }
    let credential = offer
        .payer_credential
        .to_canonical_bytes()
        .map_err(|_| Failure::code(INVALID))?;
    let certificates =
        norito::encode_canonical(&offer.certificates).map_err(|_| Failure::code(INVALID))?;
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

    fn original(name: &str) -> Vec<u8> {
        // Frozen seeded DATA vectors include stand-in proofs. They confer no wallet authority.
        let fixture: norito::json::Value = norito::json::from_str(include_str!(
            "../../../../../fixtures/kagemusha/wallet_v1_vectors.json"
        ))
        .unwrap();
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

    #[test]
    fn original_payment_and_offer_payer_are_preserved_without_proof_admission() {
        let payment = original("Payment");
        let offer_bytes = original("Offer");
        let offer: KagemushaWalletOfferV1 = decode(&offer_bytes).unwrap();
        let state::OperationActionV1::Receive {
            payment: retained,
            payer_credential,
            certificates,
        } = action(&payment, &offer_bytes).unwrap()
        else {
            panic!("Receive only")
        };
        assert_eq!(payment, retained);
        assert_eq!(
            payer_credential,
            offer.payer_credential.to_canonical_bytes().unwrap()
        );
        assert_eq!(
            certificates,
            norito::encode_canonical(&offer.certificates).unwrap()
        );
    }

    #[test]
    fn every_foreign_payer_session_binding_is_refused() {
        let payment: KagemushaWalletPaymentV1 = decode(&original("Payment")).unwrap();
        let offer = original("Offer");
        for binding in 0..8 {
            let mut changed = payment.clone();
            match binding {
                0 => changed.request.body.scheme_id[0] ^= 1,
                1 => changed.request.body.asset_digest[0] ^= 1,
                2 => changed.request.body.payer_wallet_id[0] ^= 1,
                3 => changed.request.body.payer_account_digest[0] ^= 1,
                4 => changed.request.body.send_ordinal += 1,
                5 => changed.request.body.amount += 1,
                6 => changed.payer_credential_digest[0] ^= 1,
                _ => {
                    let request: KagemushaWalletRequestV1 = decode(&original("Request")).unwrap();
                    changed.payer_payment_key = request.receiver_credential.body.payment_key;
                    assert_ne!(changed.payer_payment_key, payment.payer_payment_key);
                }
            }
            let bytes = norito::encode_canonical(&changed).unwrap();
            assert!(action(&bytes, &offer).is_err(), "binding {binding}");
        }
    }

    #[test]
    fn malformed_trailing_oversized_and_unsigned_originals_are_refused() {
        let payment = original("Payment");
        let offer = original("Offer");
        for invalid in [vec![], vec![0], vec![0; 10_001]] {
            assert!(action(&invalid, &offer).is_err());
            assert!(action(&payment, &invalid).is_err());
        }
        let mut trailing = payment.clone();
        trailing.push(0);
        assert!(action(&trailing, &offer).is_err());
        let mut trailing = offer.clone();
        trailing.push(0);
        assert!(action(&payment, &trailing).is_err());
        let mut unsigned: KagemushaWalletOfferV1 = decode(&offer).unwrap();
        unsigned.body.session_nonce[0] ^= 1;
        assert!(action(&payment, &norito::encode_canonical(&unsigned).unwrap()).is_err());
    }
}
