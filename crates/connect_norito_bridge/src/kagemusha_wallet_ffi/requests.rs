//! Shared C/JNI typed intake. Only the installed owner may decode and prepare originals.

use super::*;

mod receive_offer;

use iroha_data_model::isi::kagemusha_wallet::load_finality::KAGEMUSHA_WALLET_LOAD_RECEIPT_MAX_BYTES_V1;

/// Exact per-original bounds, applied before either foreign frontend allocates input copies.
pub(crate) fn bounds(selector: u32) -> Result<[usize; 3]> {
    let message = KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1;
    Ok(match selector {
        0 => [
            KAGEMUSHA_WALLET_LOAD_RECEIPT_MAX_BYTES_V1,
            KAGEMUSHA_WALLET_LOAD_FINALITY_MAX_BYTES_V1,
            0,
        ],
        1 => [message, 0, 0],
        2 => [message, KAGEMUSHA_WALLET_CREDENTIAL_MAX_BYTES_V1, message],
        3 => [KAGEMUSHA_WALLET_CREDENTIAL_MAX_BYTES_V1, message, 0],
        4 => [KAGEMUSHA_WALLET_SCHEME_POLICY_MAX_BYTES_V1, message, 0],
        5 => [KAGEMUSHA_WALLET_BLACKLIST_MAX_BYTES_V1, message, 0],
        6 => [KAGEMUSHA_WALLET_TIME_ANCHOR_MAX_BYTES_V1, message, 0],
        7 => [KAGEMUSHA_WALLET_QUOTA_SHARE_MAX_BYTES_V1, message, 0],
        8 => [KAGEMUSHA_WALLET_CHARGE_QUOTE_MAX_BYTES_V1, message, 0],
        9 => [0; 3],
        10 => [message, message, 0],
        _ => return Err(Failure::code(INVALID)),
    })
}

pub(crate) fn request(
    id: &[u8],
    selector: u32,
    amount: u128,
    originals: [&[u8]; 3],
) -> Result<state::OperationRequestV1> {
    let request_id: [u8; 32] = id.try_into().map_err(|_| Failure::code(INVALID))?;
    let limits = bounds(selector)?;
    if request_id == [0; 32]
        || (selector != 8 && amount != 0)
        || originals
            .iter()
            .zip(limits)
            .any(|(bytes, limit)| bytes.len() > limit)
        || ((selector < 8 || selector == 10)
            && originals
                .iter()
                .zip(limits)
                .any(|(bytes, limit)| limit != 0 && bytes.is_empty()))
    {
        return Err(Failure::code(INVALID));
    }
    use KagemushaWalletPolicyUpdateKindV1 as K;
    use state::OperationActionV1 as A;
    let [first, second, third] = originals;
    let action = match selector {
        0 => A::Load {
            receipt: first.to_vec(),
            finality: second.to_vec(),
        },
        1 => A::Send {
            request: first.to_vec(),
        },
        2 => A::Receive {
            payment: first.to_vec(),
            payer_credential: second.to_vec(),
            certificates: third.to_vec(),
        },
        3..=7 => A::Refresh {
            kind: match selector {
                3 => K::Credential,
                4 => K::SchemePolicy,
                5 => K::Blacklist,
                6 => K::TimeAnchor,
                _ => K::QuotaShare,
            },
            update: first.to_vec(),
            certificates: second.to_vec(),
        },
        8 => {
            if amount == 0 || first.is_empty() != second.is_empty() {
                return Err(Failure::code(INVALID));
            }
            A::Unload {
                amount,
                charge: (!first.is_empty()).then(|| state::ChargeOriginalsV1 {
                    quote: first.to_vec(),
                    certificates: second.to_vec(),
                }),
            }
        }
        9 => A::Retire,
        10 => receive_offer::action(first, second)?,
        _ => return Err(Failure::code(INVALID)),
    };
    Ok(state::OperationRequestV1 { request_id, action })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_selector_has_exact_bounded_originals_and_no_unused_fields() {
        for selector in 0..=9 {
            let limits = bounds(selector).unwrap();
            let originals = limits.map(|limit| if limit == 0 { vec![] } else { vec![7] });
            let refs = originals.each_ref().map(Vec::as_slice);
            let amount = if selector == 8 { u128::MAX } else { 0 };
            let admitted = request(&[1; 32], selector, amount, refs).unwrap();
            assert_eq!(admitted.request_id, [1; 32]);
            if selector == 8 {
                assert!(matches!(
                    admitted.action,
                    state::OperationActionV1::Unload {
                        amount: u128::MAX,
                        ..
                    }
                ));
            }
            for index in 0..3 {
                let mut changed = originals.clone();
                changed[index] = vec![0; limits[index] + 1];
                assert_eq!(
                    request(
                        &[1; 32],
                        selector,
                        amount,
                        changed.each_ref().map(Vec::as_slice)
                    )
                    .unwrap_err()
                    .status,
                    INVALID
                );
            }
            assert!(request(&[0; 32], selector, amount, refs).is_err());
            assert!(request(&[1; 31], selector, amount, refs).is_err());
            if selector != 8 {
                assert!(request(&[1; 32], selector, 1, refs).is_err());
            }
        }
        assert_eq!(bounds(10).unwrap(), [10_000, 10_000, 0]);
        assert!(bounds(11).is_err());
        assert!(request(&[1; 32], 10, 0, [&[], &[], &[]]).is_err());
        assert!(request(&[1; 32], 8, 0, [&[]; 3]).is_err());
        assert!(request(&[1; 32], 8, 1, [&[1], &[], &[]]).is_err());
        assert!(request(&[1; 32], 8, 1, [&[], &[1], &[]]).is_err());
        assert!(request(&[1; 32], 8, 1, [&[]; 3]).is_ok());
    }
}
