//! Exact native Envelope framing only; this grants no monetary or delivery authority.
use super::*;

pub(super) fn convert(kind: u8, wrap: bool, original: &[u8], scheme: &[u8; 32]) -> Result<Vec<u8>> {
    if original.is_empty() || original.len() > KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1 {
        return Err(Failure::code(INVALID));
    }
    let envelope = if wrap {
        let message = match kind {
            1 => KagemushaWalletMessageV1::Offer {
                offer: decode(original)?,
            },
            2 => KagemushaWalletMessageV1::Request {
                request: decode(original)?,
            },
            3 => KagemushaWalletMessageV1::Payment {
                payment: decode(original)?,
            },
            4 => KagemushaWalletMessageV1::Credited {
                credited: decode(original)?,
            },
            _ => return Err(Failure::code(INVALID)),
        };
        KagemushaWalletEnvelopeV1::new(message)
    } else {
        KagemushaWalletEnvelopeV1::decode_canonical(original, scheme)
            .map_err(|_| Failure::code(INVALID))?
    };
    if envelope.message.tag() != kind || envelope.message.scheme_id() != scheme {
        return Err(Failure::code(INVALID));
    }
    if wrap {
        // A raw object has not yet passed full-Envelope validation or its per-kind bound.
        return envelope
            .to_canonical_bytes()
            .map_err(|_| Failure::code(INVALID));
    }
    // decode_canonical already validated the message representation and enforced the
    // complete Envelope bound. Do not verify and serialize that same envelope a second time.
    let object = match envelope.message {
        KagemushaWalletMessageV1::Offer { offer } => norito::encode_canonical(&offer),
        KagemushaWalletMessageV1::Request { request } => norito::encode_canonical(&request),
        KagemushaWalletMessageV1::Payment { payment } => norito::encode_canonical(&payment),
        KagemushaWalletMessageV1::Credited { credited } => norito::encode_canonical(&credited),
        _ => return Err(Failure::code(INVALID)),
    };
    object.map_err(|_| Failure::code(INVALID))
}
/// Project an exact native Receive/Status output into its peer response carrier.
/// This validates representation, scheme and the complete envelope bound only.
pub(super) fn credited(status: bool, original: &[u8], scheme: &[u8; 32]) -> Result<Vec<u8>> {
    if original.is_empty() || original.len() > KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1 {
        return Err(Failure::code(INVALID));
    }
    let credited = if status {
        KagemushaWalletCreditedV1::from_status(decode(original)?)
    } else {
        KagemushaWalletCreditedV1::from_receive(decode(original)?)
    }
    .map_err(|_| Failure::code(INVALID))?;
    let bytes = norito::encode_canonical(&credited).map_err(|_| Failure::code(INVALID))?;
    let envelope = KagemushaWalletEnvelopeV1::new(KagemushaWalletMessageV1::Credited { credited });
    if bytes.len() > KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1 || envelope.message.scheme_id() != scheme
    {
        return Err(Failure::code(INVALID));
    }
    // Validate the object already decoded above through the same full-Envelope owner.
    // Re-decoding our just-encoded Credited bytes would only repeat canonical codec work.
    envelope
        .to_canonical_bytes()
        .map_err(|_| Failure::code(INVALID))?;
    Ok(bytes)
}
fn decode<T>(original: &[u8]) -> Result<T>
where
    T: norito::NoritoSerialize,
    for<'de> T: norito::NoritoDeserialize<'de>,
{
    norito::decode_canonical_with_limits(original, norito::canonical_decode_limits(original.len()))
        .map_err(|_| Failure::code(INVALID))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_transport_roundtrip_and_replay_preserve_all_original_bytes() {
        let vectors: norito::json::Value = norito::json::from_str(include_str!(
            "../../../../fixtures/kagemusha/wallet_v1_vectors.json"
        ))
        .unwrap();
        for (kind, name) in [
            (1, "Offer"),
            (2, "Request"),
            (3, "Payment"),
            (4, "Credited"),
        ] {
            let row = vectors["envelopes"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["kind"].as_str() == Some(name))
                .unwrap();
            let known_frame = hex::decode(row["canonical_hex"].as_str().unwrap()).unwrap();
            let scheme: [u8; 32] = hex::decode(row["scheme_id_hex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            let original = convert(kind, false, &known_frame, &scheme).unwrap();
            let frame = convert(kind, true, &original, &scheme).unwrap();
            assert_eq!(frame, known_frame);
            assert_eq!(frame, convert(kind, true, &original, &scheme).unwrap());
            assert_eq!(original, convert(kind, false, &frame, &scheme).unwrap());
            assert!(frame.len() <= KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1);
            assert!(convert(kind, true, &original, &[0; 32]).is_err());
            assert!(convert(kind, false, &frame, &[0; 32]).is_err());
            assert!(convert(kind % 4 + 1, false, &frame, &scheme).is_err());
            let mut trailing = frame.clone();
            trailing.push(0);
            assert!(convert(kind, false, &trailing, &scheme).is_err());
            let mut trailing = original;
            trailing.push(0);
            assert!(convert(kind, true, &trailing, &scheme).is_err());
            assert!(convert(kind, false, &vec![0; 10_001], &scheme).is_err());
        }
    }
    #[test]
    fn extraction_preserves_version_signature_and_full_envelope_bound_checks() {
        let vectors: norito::json::Value = norito::json::from_str(include_str!(
            "../../../../fixtures/kagemusha/wallet_v1_vectors.json"
        ))
        .unwrap();
        let row = vectors["envelopes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["kind"].as_str() == Some("Offer"))
            .unwrap();
        let frame = hex::decode(row["canonical_hex"].as_str().unwrap()).unwrap();
        let scheme: [u8; 32] = hex::decode(row["scheme_id_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let envelope = KagemushaWalletEnvelopeV1::decode_canonical(&frame, &scheme).unwrap();
        let mut wrong_version = envelope.clone();
        wrong_version.version += 1;
        assert!(
            convert(
                1,
                false,
                &norito::encode_canonical(&wrong_version).unwrap(),
                &scheme
            )
            .is_err()
        );
        let KagemushaWalletMessageV1::Offer { offer } = envelope.message else {
            panic!("canonical Offer fixture");
        };
        let mut changed_offer = offer.clone();
        changed_offer.body.amount += 1;
        let changed = KagemushaWalletEnvelopeV1::new(KagemushaWalletMessageV1::Offer {
            offer: changed_offer,
        });
        assert!(
            convert(
                1,
                false,
                &norito::encode_canonical(&changed).unwrap(),
                &scheme
            )
            .is_err()
        );

        let certificate = offer.certificates.certificates[0].clone();
        for count in 2..=32 {
            let mut enlarged = offer.clone();
            enlarged.certificates.certificates = vec![certificate.clone(); count];
            let enlarged =
                KagemushaWalletEnvelopeV1::new(KagemushaWalletMessageV1::Offer { offer: enlarged });
            let frame = norito::encode_canonical(&enlarged).unwrap();
            if frame.len() > KAGEMUSHA_WALLET_SESSION_MAX_BYTES_V1 {
                // This passes the bridge's global cap, so the model's stricter Offer
                // envelope limit must still reject it before message validation.
                assert!(frame.len() <= KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1);
                assert!(matches!(
                    KagemushaWalletEnvelopeV1::decode_canonical(&frame, &scheme),
                    Err(KagemushaWalletValidationErrorV1::EncodedSizeExceeded { .. })
                ));
                assert!(convert(1, false, &frame, &scheme).is_err());
                return;
            }
        }
        panic!("fixture did not exceed the Offer envelope bound");
    }
    #[test]
    fn credited_projection_preserves_both_native_outputs_and_rejects_other_sources() {
        let vectors: norito::json::Value = norito::json::from_str(include_str!(
            "../../../../fixtures/kagemusha/wallet_v1_vectors.json"
        ))
        .unwrap();
        let mut variants = [false; 2];
        for row in vectors["envelopes"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["kind"].as_str() == Some("Credited"))
        {
            let frame = hex::decode(row["canonical_hex"].as_str().unwrap()).unwrap();
            let scheme: [u8; 32] = hex::decode(row["scheme_id_hex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            let expected = convert(4, false, &frame, &scheme).unwrap();
            let carrier: KagemushaWalletCreditedV1 = decode(&expected).unwrap();
            let (is_status, source) = match carrier.evidence {
                KagemushaWalletCreditedEvidenceV1::Receive { package } => {
                    (false, norito::encode_canonical(&package).unwrap())
                }
                KagemushaWalletCreditedEvidenceV1::Status { status } => {
                    (true, norito::encode_canonical(&status).unwrap())
                }
            };
            variants[usize::from(is_status)] = true;
            assert_eq!(credited(is_status, &source, &scheme).unwrap(), expected);
            assert_eq!(credited(is_status, &source, &scheme).unwrap(), expected);
            assert_eq!(convert(4, true, &expected, &scheme).unwrap(), frame);
            assert!(credited(!is_status, &source, &scheme).is_err());
            assert!(credited(is_status, &source, &[0; 32]).is_err());
            let mut trailing = source;
            trailing.push(0);
            assert!(credited(is_status, &trailing, &scheme).is_err());
        }
        assert_eq!(variants, [true; 2]);
        let row = vectors["envelopes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["kind"].as_str() == Some("Payment"))
            .unwrap();
        let frame = hex::decode(row["canonical_hex"].as_str().unwrap()).unwrap();
        let scheme = hex::decode(row["scheme_id_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let payment: KagemushaWalletPaymentV1 =
            decode(&convert(3, false, &frame, &scheme).unwrap()).unwrap();
        assert!(
            credited(
                false,
                &norito::encode_canonical(&payment.send).unwrap(),
                &scheme
            )
            .is_err()
        );
        for status in [false, true] {
            assert!(credited(status, &[], &scheme).is_err());
            assert!(credited(status, &vec![0; 10_001], &scheme).is_err());
        }
    }
}
