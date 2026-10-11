//! Fixed G1 frame alignment on every native target, including `ARMv7`.
//!
//! Norito framing uses the Rust type's archived storage alignment. Wallet types
//! containing a direct u128 pin that alignment to 16 bytes; ordinary enclosing
//! fields and inline fixed arrays propagate it; indirect Vec storage does not.
//! This preserves the existing G1
//! header/padding/payload contract without another codec or target-dependent path.
//! Compile-time assertions run in the shipping library, including cross builds.

use super::*;
#[cfg(test)]
use crate::isi::kagemusha_wallet::load_finality::KAGEMUSHA_WALLET_LOAD_RECEIPT_MAX_BYTES_V1;
use crate::isi::kagemusha_wallet::load_finality::KagemushaWalletLoadReceiptV1;

const fn canonical_padding<T>() -> usize {
    let alignment = norito::core::archived_payload_align::<T>();
    let remainder = norito::core::Header::SIZE % alignment;
    if remainder == 0 {
        0
    } else {
        alignment - remainder
    }
}

// Every direct u128 root is pinned, including map/payout records which can be
// retained or framed outside one of the 28 bounded standalone object types.
const _: () = {
    assert!(norito::core::archived_payload_align::<KagemushaWalletMarkerStateV1>() == 16);
    assert!(norito::core::archived_payload_align::<KagemushaWalletMarkerV1>() == 16);
    assert!(norito::core::archived_payload_align::<KagemushaWalletFoldRecordV1>() == 16);
    assert!(norito::core::archived_payload_align::<KagemushaWalletLoadReceiptV1>() == 16);
    assert!(norito::core::archived_payload_align::<KagemushaWalletUnloadPayoutV1>() == 16);
    assert!(norito::core::archived_payload_align::<KagemushaWalletFeePayoutV1>() == 16);
    assert!(norito::core::archived_payload_align::<KagemushaWalletLedgerControlActionV1>() == 16);
    assert!(norito::core::archived_payload_align::<KagemushaWalletPayoutRecordV1>() == 16);
    assert!(norito::core::archived_payload_align::<KagemushaWalletOfferBodyV1>() == 16);
    assert!(norito::core::archived_payload_align::<KagemushaWalletRequestBodyV1>() == 16);
    assert!(norito::core::archived_payload_align::<KagemushaWalletFeeScheduleBodyV1>() == 16);
    assert!(norito::core::archived_payload_align::<KagemushaWalletQuotaWindowV1>() == 16);
    assert!(norito::core::archived_payload_align::<KagemushaWalletChargeQuoteBodyV1>() == 16);
    assert!(norito::core::archived_payload_align::<KagemushaWalletStateCoreV1>() == 16);
    assert!(norito::core::archived_payload_align::<KagemushaWalletConsumedCreditLeafV1>() == 16);
    assert!(norito::core::archived_payload_align::<KagemushaWalletPendingOutgoingLeafV1>() == 16);
    assert!(norito::core::archived_payload_align::<KagemushaWalletLoadLeafV1>() == 16);
    assert!(norito::core::archived_payload_align::<KagemushaWalletRedeemLeafV1>() == 16);
    assert!(norito::core::archived_payload_align::<KagemushaWalletFeeClaimLeafV1>() == 16);
    assert!(norito::core::archived_payload_align::<KagemushaWalletQuotaUsageLeafV1>() == 16);
    assert!(norito::core::archived_payload_align::<KagemushaWalletSendChainEntryV1>() == 16);
    assert!(norito::core::archived_payload_align::<KagemushaWalletRecvChainEntryV1>() == 16);
    assert!(norito::core::archived_payload_align::<KagemushaWalletEffectV1>() == 16);
    assert!(norito::core::archived_payload_align::<KagemushaWalletStatementV1>() == 16);
    assert!(norito::core::archived_payload_align::<KagemushaWalletLineagePublicV1>() == 16);
    assert!(norito::core::archived_payload_align::<KagemushaWalletReceiptBodyV1>() == 16);
};

macro_rules! assert_frame_padding {
    ($($ty:ident => $padding:literal, $maximum:ident);+ $(;)?) => {
        const _: () = {
            $(assert!(canonical_padding::<$ty>() == $padding);)+
        };
        #[cfg(test)]
        fn check_frozen_frame(name: &str, frame: &[u8]) -> bool {
            match name {
                $(stringify!($ty) => {
                    tests::check_frame::<$ty>(frame, $padding, $maximum);
                    true
                },)+
                _ => false,
            }
        }
    };
}

// The exact existing §2 table, including zero padding for Vec-only u128
// objects such as QuotaShareV1 and CompletionRecordV1.
assert_frame_padding! {
    KagemushaWalletEnvelopeV1 => 8, KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1;
    KagemushaWalletSchemeV1 => 0, KAGEMUSHA_WALLET_SCHEME_MAX_BYTES_V1;
    KagemushaWalletSignerCertificateV1 => 0, KAGEMUSHA_WALLET_CERTIFICATE_MAX_BYTES_V1;
    KagemushaWalletCredentialV1 => 0, KAGEMUSHA_WALLET_CREDENTIAL_MAX_BYTES_V1;
    KagemushaWalletRenewalRequestV1 => 0, KAGEMUSHA_WALLET_RENEWAL_REQUEST_MAX_BYTES_V1;
    KagemushaWalletArtifactManifestV1 => 0, KAGEMUSHA_WALLET_ARTIFACT_MANIFEST_MAX_BYTES_V1;
    KagemushaWalletVerifyingKeyAllowlistV1 => 0, KAGEMUSHA_WALLET_VERIFYING_KEY_ALLOWLIST_MAX_BYTES_V1;
    KagemushaWalletSchemePolicyV1 => 0, KAGEMUSHA_WALLET_SCHEME_POLICY_MAX_BYTES_V1;
    KagemushaWalletFeeScheduleV1 => 8, KAGEMUSHA_WALLET_FEE_SCHEDULE_MAX_BYTES_V1;
    KagemushaWalletBlacklistV1 => 0, KAGEMUSHA_WALLET_BLACKLIST_MAX_BYTES_V1;
    KagemushaWalletQuotaShareV1 => 0, KAGEMUSHA_WALLET_QUOTA_SHARE_MAX_BYTES_V1;
    KagemushaWalletQuotaRefreshWitnessV1 => 8, KAGEMUSHA_WALLET_QUOTA_REFRESH_WITNESS_MAX_BYTES_V1;
    KagemushaWalletTimeAnchorV1 => 0, KAGEMUSHA_WALLET_TIME_ANCHOR_MAX_BYTES_V1;
    KagemushaWalletChargeQuoteV1 => 8, KAGEMUSHA_WALLET_CHARGE_QUOTE_MAX_BYTES_V1;
    KagemushaWalletPaymentV1 => 8, KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1;
    KagemushaWalletPackageV1 => 8, KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1;
    KagemushaWalletMarkerV1 => 8, KAGEMUSHA_WALLET_MARKER_MAX_BYTES_V1;
    KagemushaWalletRecoveryCapsuleV1 => 8, KAGEMUSHA_WALLET_CAPSULE_MAX_BYTES_V1;
    KagemushaWalletCompletionRecordV1 => 0, KAGEMUSHA_WALLET_COMPLETION_RECORD_MAX_BYTES_V1;
    KagemushaWalletFoldRecordV1 => 8, KAGEMUSHA_WALLET_FOLD_RECORD_MAX_BYTES_V1;
    KagemushaWalletLoadReceiptV1 => 8, KAGEMUSHA_WALLET_LOAD_RECEIPT_MAX_BYTES_V1;
    KagemushaWalletLoadFinalityV1 => 0, KAGEMUSHA_WALLET_LOAD_FINALITY_MAX_BYTES_V1;
    KagemushaWalletUnloadClaimV1 => 8, KAGEMUSHA_WALLET_UNLOAD_CLAIM_MAX_BYTES_V1;
    KagemushaWalletFeeClaimV1 => 8, KAGEMUSHA_WALLET_FEE_CLAIM_MAX_BYTES_V1;
    KagemushaWalletLedgerControlV1 => 8, KAGEMUSHA_WALLET_LEDGER_CONTROL_MAX_BYTES_V1;
    KagemushaWalletActivationV1 => 8, KAGEMUSHA_WALLET_ACTIVATION_MAX_BYTES_V1;
    KagemushaWalletCloseLoadsV1 => 8, KAGEMUSHA_WALLET_CLOSE_LOADS_MAX_BYTES_V1;
    KagemushaWalletAbandonmentV1 => 8, KAGEMUSHA_WALLET_ABANDONMENT_MAX_BYTES_V1;
}

// These retained originals and opened witness records are also framed by native
// custody/proof intake, even though they have no separate §2 top-level cap.
const _: () = {
    assert!(canonical_padding::<KagemushaWalletRequestV1>() == 8);
    assert!(canonical_padding::<KagemushaWalletLineageV1>() == 8);
    assert!(canonical_padding::<KagemushaWalletLineageMessageV1>() == 8);
    assert!(canonical_padding::<KagemushaWalletStateV1>() == 8);
    assert!(canonical_padding::<KagemushaWalletStatementV1>() == 8);
    assert!(canonical_padding::<KagemushaWalletReceiptV1>() == 0);
};

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use norito::json::Value;

    use super::*;

    fn vectors() -> Value {
        norito::json::parse_value(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/kagemusha/wallet_v1_vectors.json"
        )))
        .expect("frozen wallet fixture")
    }

    fn original(row: &norito::json::Map) -> Vec<u8> {
        let Value::String(text) = row.get("canonical_hex").expect("canonical hex") else {
            panic!("canonical hex must be a string");
        };
        hex::decode(text).expect("frozen original hex")
    }

    /// Decode actual frozen bytes and require their one existing canonical spelling.
    pub(super) fn check_frame<T>(frame: &[u8], padding: usize, maximum: usize)
    where
        T: norito::NoritoSerialize + for<'de> norito::NoritoDeserialize<'de>,
    {
        assert!(frame.len() <= maximum, "existing complete-frame cap");
        let header = norito::core::Header::read(frame).expect("original header");
        assert_eq!(header.flags, 0x02);
        let payload_bytes = usize::try_from(header.length).expect("bounded fixture payload");
        assert_eq!(
            frame.len(),
            norito::core::Header::SIZE + padding + payload_bytes
        );
        assert!(frame[40..40 + padding].iter().all(|byte| *byte == 0));
        let value: T = norito::decode_canonical_with_limits(
            frame,
            norito::canonical_decode_limits(frame.len()),
        )
        .expect("frozen canonical decode");
        assert_eq!(norito::encode_canonical(&value).expect("re-encode"), frame);
        assert_eq!(
            norito::canonical_frame_len(&value).expect("canonical frame count"),
            frame.len()
        );
        norito::verify_exact_canonical_frame(&value, frame).expect("exact original spelling");
        let mut alternate = frame.to_vec();
        if padding == 8 {
            drop(alternate.drain(40..48));
            let mut nonzero = frame.to_vec();
            nonzero[40] = 1;
            assert!(norito::decode_canonical::<T>(&nonzero).is_err());
        } else {
            drop(alternate.splice(40..40, [0; 8]));
        }
        assert!(
            norito::decode_canonical::<T>(&alternate).is_err(),
            "alternate padding rejected"
        );
    }

    #[test]
    fn kagemusha_wallet_v1_frozen_frames_preserve_all_28_padding_contracts() {
        let Value::Object(document) = vectors() else {
            panic!("fixture object");
        };
        let Value::Array(objects) = document.get("objects").expect("objects") else {
            panic!("objects array");
        };
        let mut covered = BTreeSet::new();
        for object in objects {
            let Value::Object(row) = object else {
                panic!("object row");
            };
            let Value::String(name) = row.get("type").expect("type") else {
                panic!("type string");
            };
            if check_frozen_frame(name, &original(row)) {
                covered.insert(name.as_str());
            }
        }
        let Value::Array(envelopes) = document.get("envelopes").expect("envelopes") else {
            panic!("envelopes array");
        };
        for envelope in envelopes {
            let Value::Object(row) = envelope else {
                panic!("envelope row");
            };
            let frame = original(row);
            assert!(check_frozen_frame("KagemushaWalletEnvelopeV1", &frame));
            let value: KagemushaWalletEnvelopeV1 =
                norito::decode_canonical(&frame).expect("envelope");
            assert_eq!(
                value.to_canonical_bytes().expect("existing per-kind bound"),
                frame
            );
        }
        covered.insert("KagemushaWalletEnvelopeV1");
        let Value::Array(frames) = document.get("frames").expect("frames") else {
            panic!("frames array");
        };
        assert_eq!(covered.len(), 28);
        assert_eq!(frames.len(), covered.len());
        for frame in frames {
            let Value::Object(row) = frame else {
                panic!("frame row");
            };
            let Value::String(name) = row.get("type").expect("frame type") else {
                panic!("frame type string");
            };
            assert!(
                covered.contains(name.as_str()),
                "every frozen frame type is covered"
            );
        }
    }

    #[test]
    fn kagemusha_wallet_v1_retained_request_and_lineage_inherit_fixed_padding() {
        let Value::Object(document) = vectors() else {
            panic!("fixture object");
        };
        let Value::Array(envelopes) = document.get("envelopes").expect("envelopes") else {
            panic!("envelopes array");
        };
        let mut requests = 0;
        let mut lineages = 0;
        for envelope in envelopes {
            let Value::Object(row) = envelope else {
                panic!("envelope row");
            };
            let value: KagemushaWalletEnvelopeV1 =
                norito::decode_canonical(&original(row)).expect("frozen envelope");
            match value.message {
                KagemushaWalletMessageV1::Request { request } => {
                    let frame = norito::encode_canonical(&request).expect("retained Request");
                    check_frame::<KagemushaWalletRequestV1>(
                        &frame,
                        8,
                        KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1,
                    );
                    requests += 1;
                }
                KagemushaWalletMessageV1::Lineage { lineage } => {
                    let frame =
                        norito::encode_canonical(&lineage.lineage).expect("retained Lineage");
                    check_frame::<KagemushaWalletLineageV1>(
                        &frame,
                        8,
                        KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1,
                    );
                    lineages += 1;
                }
                _ => {}
            }
        }
        assert!(requests > 0);
        assert!(lineages > 0);
    }
}
