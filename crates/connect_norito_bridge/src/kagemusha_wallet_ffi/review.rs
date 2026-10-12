//! Owner-local one-use financial review. Projection bytes are DATA, never authority.
use super::*;
use exports::{input, output};

const FINANCIAL_BYTES: usize = 491;
pub(crate) const PROJECTION_FIXED_BYTES: usize = FINANCIAL_BYTES + 4;
const ACCOUNT_MAX: usize = iroha_core_zk::kagemusha_wallet_intake_v1::ACCOUNT_ORIGINAL_MAX_BYTES_V1;
const MAX_REVIEWS: usize = 8;
const MAGIC: &[u8; 8] = b"KWORV1\0\0";
const CHARGE_MAGIC: &[u8; 8] = b"KWUCV1\0\0";
const CHARGE_CARRIER_MAX: usize = 16 + KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1 + ACCOUNT_MAX;

/// One fixed request for Native to authenticate; no foreign state or financial verdict.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WalletReviewRequest {
    /// Send1 or Unload8 only.
    pub selector: u32,
    /// Unload face amount only; zero for Send.
    pub amount: WalletU128,
    /// Complete Request for Send, optional original charge quote for Unload.
    pub first: *const u8,
    /// Exact first-original length.
    pub first_length: usize,
    /// Canonical destination AccountId for Send; closed certificate/beneficiary DATA for Unload.
    pub second: *const u8,
    /// Exact second-original length.
    pub second_length: usize,
}
pub(crate) enum Input {
    Send {
        request: Vec<u8>,
        destination_account: Vec<u8>,
    },
    Unload {
        amount: u128,
        charge: Option<state::ChargeOriginalsV1>,
        beneficiary: Option<Vec<u8>>,
    },
}
pub(crate) fn bounds(selector: u32) -> Result<[usize; 2]> {
    Ok(match selector {
        1 => [KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1, ACCOUNT_MAX],
        8 => [
            KAGEMUSHA_WALLET_CHARGE_QUOTE_MAX_BYTES_V1,
            CHARGE_CARRIER_MAX,
        ],
        _ => return Err(Failure::code(INVALID)),
    })
}
fn unload_charge_carrier(second: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let invalid = || Failure::code(INVALID);
    if second.len() < 18 || second.len() > CHARGE_CARRIER_MAX || &second[..8] != CHARGE_MAGIC {
        return Err(invalid());
    }
    let certificates =
        u32::from_le_bytes(second[8..12].try_into().map_err(|_| invalid())?) as usize;
    if certificates == 0 || certificates > KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1 {
        return Err(invalid());
    }
    let beneficiary_offset = 12 + certificates;
    let length = second
        .get(beneficiary_offset..beneficiary_offset + 4)
        .ok_or_else(invalid)?;
    let beneficiary = u32::from_le_bytes(length.try_into().map_err(|_| invalid())?) as usize;
    if beneficiary == 0
        || beneficiary > ACCOUNT_MAX
        || second.len() != beneficiary_offset + 4 + beneficiary
    {
        return Err(invalid());
    }
    Ok((
        second[12..beneficiary_offset].to_vec(),
        second[beneficiary_offset + 4..].to_vec(),
    ))
}
pub(crate) fn request(selector: u32, amount: u128, first: &[u8], second: &[u8]) -> Result<Input> {
    let b = bounds(selector)?;
    if first.len() > b[0] || second.len() > b[1] {
        return Err(Failure::code(INVALID));
    }
    Ok(match selector {
        1 if amount == 0 && !first.is_empty() && !second.is_empty() => Input::Send {
            request: first.to_vec(),
            destination_account: second.to_vec(),
        },
        8 if amount != 0 && first.is_empty() && second.is_empty() => Input::Unload {
            amount,
            charge: None,
            beneficiary: None,
        },
        8 if amount != 0 && !first.is_empty() => {
            let (certificates, beneficiary) = unload_charge_carrier(second)?;
            Input::Unload {
                amount,
                charge: Some(state::ChargeOriginalsV1 {
                    quote: first.to_vec(),
                    certificates,
                }),
                beneficiary: Some(beneficiary),
            }
        }
        _ => return Err(Failure::code(INVALID)),
    })
}
// Financial review, deletion review and direct-time capabilities share one process sequence.
// A numeric token from another owner or purpose cannot alias any outstanding capability.
static NEXT_CAPABILITY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub(super) fn allocate_token() -> Result<u64> {
    allocate_from(&NEXT_CAPABILITY)
}
fn allocate_from(next: &std::sync::atomic::AtomicU64) -> Result<u64> {
    use std::sync::atomic::Ordering;
    next.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        value
            .checked_add(1)
            .filter(|value| *value <= i64::MAX as u64)
    })
    .map(|value| value + 1)
    .map_err(|_| Failure::code(RESOURCE))
}

/// This private owner-local table holds actual non-Clone Native capabilities.
/// It never imports a capability from its copyable projection or token.
pub(super) struct Tokens<T> {
    values: BTreeMap<u64, T>,
}
impl<T> Default for Tokens<T> {
    fn default() -> Self {
        Self {
            values: BTreeMap::new(),
        }
    }
}
impl<T> Tokens<T> {
    pub(super) fn capacity(&self) -> Result<()> {
        if self.values.len() >= MAX_REVIEWS {
            Err(Failure::code(RESOURCE))
        } else {
            Ok(())
        }
    }
    pub(super) fn put(&mut self, value: T) -> Result<u64> {
        self.capacity()?;
        let id = allocate_token()?;
        self.values.insert(id, value);
        Ok(id)
    }
    pub(super) fn clear(&mut self) {
        self.values.clear();
    }
    pub(super) fn take(&mut self, token: u64) -> Result<T> {
        self.values.remove(&token).ok_or(Failure::code(INVALID))
    }
}
fn projection(value: &state::NativeOperationReviewV1) -> Result<Vec<u8>> {
    let selector = match value.kind {
        KagemushaWalletOperationKindV1::Send => 1,
        KagemushaWalletOperationKindV1::Unload => 8,
        _ => return Err(Failure::code(INTERNAL)),
    };
    let account = match (selector, value.destination_account_original.as_deref()) {
        (1, Some(original)) if !original.is_empty() && original.len() <= ACCOUNT_MAX => original,
        (8, None) => &[],
        _ => return Err(Failure::code(INTERNAL)),
    };
    let mut out = Vec::with_capacity(PROJECTION_FIXED_BYTES + account.len());
    out.extend_from_slice(MAGIC);
    out.push(selector);
    for amount in [
        value.amount,
        value.fee,
        value.gross_debit,
        value.net_destination_amount,
    ] {
        out.extend_from_slice(&amount.to_le_bytes());
    }
    out.push(u8::from(value.receiver_wallet_id.is_some()));
    out.extend_from_slice(&value.receiver_wallet_id.unwrap_or([0; 32]));
    for digest in [
        value.destination_account_digest,
        value.request_digest,
        value.charge_quote_digest,
        value.scheme_id,
        value.wallet_id,
        value.current_head,
        value.source_state_commitment,
        value.source_capsule_digest,
        value.credential_digest,
        value.artifact_manifest_digest,
    ] {
        out.extend_from_slice(&digest);
    }
    out.extend_from_slice(value.payment_key.as_sec1_bytes());
    if out.len() != FINANCIAL_BYTES {
        return Err(Failure::code(INTERNAL));
    }
    out.extend_from_slice(&(account.len() as u32).to_le_bytes());
    out.extend_from_slice(account);
    Ok(out)
}
impl<P: advance::KagemushaWalletPlatformV1, S: OriginalSourceV1 + Send> NativeWallet<P, S> {
    pub(super) fn review_inner(&mut self, input: Input) -> Result<Response> {
        self.reviews.capacity()?;
        let review = match input {
            Input::Send {
                request,
                destination_account,
            } => self.wallet.review_send(&request, &destination_account)?,
            Input::Unload {
                amount,
                charge,
                beneficiary,
            } => self
                .wallet
                .review_unload(amount, charge, beneficiary.as_deref())?,
        };
        let bytes = projection(review.projection())?;
        let token = self.reviews.put(review)?;
        Ok(Response {
            kind: 18,
            sequence: u128::from(token),
            bytes,
            ..Response::default()
        })
    }
    pub(super) fn execute_reviewed_inner(
        &mut self,
        token: u64,
        request: [u8; 32],
    ) -> Result<Response> {
        // Consume even on an invalid identity, failed source recheck or failed execution.
        let reviewed = self.reviews.take(token)?;
        completion(Some(self.wallet.execute_reviewed(reviewed, request)?))
    }
}
pub(crate) fn review(id: u64, input: Input) -> Result<Response> {
    with_wallet(id, true, |wallet| wallet.review(input))
}
pub(crate) fn execute_reviewed(id: u64, token: u64, request: &[u8]) -> Result<Response> {
    let request = request.try_into().map_err(|_| Failure::code(INVALID))?;
    with_wallet(id, true, |wallet| wallet.execute_reviewed(token, request))
}
pub(crate) fn discard_review(id: u64, token: u64) -> Result<()> {
    with_wallet(id, true, |wallet| wallet.discard_review(token))
}

/// Authenticate Send/Unload and retain the genuine one-use review. No monetary operation.
/// Result18 contains the491-byte financial prefix, LE u32 account length and exact
/// authenticated AccountId DATA (Send1..4096; Unload0), with an owner-local one-use token.
/// # Safety
/// Caller supplies initialized inputs and writable result memory for stated lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_kagemusha_wallet_review_v1(
    handle: u64,
    request: *const WalletReviewRequest,
    out: *mut WalletResult,
) -> i32 {
    let mut retained = None;
    let status = unsafe {
        output(out, || {
            if request.is_null() {
                return Err(Failure::code(INVALID));
            }
            let req = &*request;
            let b = bounds(req.selector)?;
            let first = input(req.first, req.first_length, b[0])?;
            let second = input(req.second, req.second_length, b[1])?;
            let amount = u128::from(req.amount.low) | (u128::from(req.amount.high) << 64);
            let result = review(handle, self::request(req.selector, amount, first, second)?)?;
            retained = Some(result.sequence as u64);
            Ok(result)
        })
    };
    if status < 0
        && let Some(token) = retained
    {
        let _ = run(|| discard_review(handle, token));
    }
    status
}
/// Consume the actual retained review after fresh hardware UI approval; source is rechecked.
/// No amount, destination, signature body or financial verdict is accepted from foreign code.
/// # Safety
/// request_id points to exactly32 initialized bytes; result is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect_norito_kagemusha_wallet_execute_reviewed_v1(
    handle: u64,
    token: u64,
    request_id: *const u8,
    out: *mut WalletResult,
) -> i32 {
    unsafe {
        output(out, || {
            let request = match input(request_id, 32, 32) {
                Ok(value) => value,
                Err(error) => {
                    let _ = discard_review(handle, token);
                    return Err(error);
                }
            };
            execute_reviewed(handle, token, request)
        })
    }
}
/// Drop one owner-local review on cancellation. Never affects durable monetary custody.
#[unsafe(no_mangle)]
pub extern "C" fn connect_norito_kagemusha_wallet_discard_review_v1(
    handle: u64,
    token: u64,
) -> i32 {
    run(|| discard_review(handle, token))
        .err()
        .map_or(0, |error| error.status)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn charge_carrier(certificates: &[u8], beneficiary: &[u8]) -> Vec<u8> {
        let mut bytes = CHARGE_MAGIC.to_vec();
        bytes.extend_from_slice(&(certificates.len() as u32).to_le_bytes());
        bytes.extend_from_slice(certificates);
        bytes.extend_from_slice(&(beneficiary.len() as u32).to_le_bytes());
        bytes.extend_from_slice(beneficiary);
        bytes
    }
    #[test]
    fn charged_review_carrier_is_closed_bounded_and_keeps_exact_originals() {
        let certificates = vec![7; 10_000];
        let beneficiary = vec![8; ACCOUNT_MAX];
        let bytes = charge_carrier(&certificates, &beneficiary);
        assert_eq!(bytes.len(), CHARGE_CARRIER_MAX);
        assert_eq!(bounds(8).unwrap(), [1_024, 14_112]);
        let Input::Unload {
            charge,
            beneficiary: actual,
            ..
        } = request(8, 1, &[9], &bytes).unwrap()
        else {
            panic!("Unload input");
        };
        assert_eq!(charge.unwrap().certificates, certificates);
        assert_eq!(actual, Some(beneficiary));
        for invalid in [
            vec![7; 10_000],
            charge_carrier(&[], &[8]),
            charge_carrier(&[7], &[]),
            charge_carrier(&vec![7; 10_001], &[8]),
            charge_carrier(&[7], &vec![8; ACCOUNT_MAX + 1]),
            bytes[..bytes.len() - 1].to_vec(),
            [bytes.as_slice(), &[0]].concat(),
        ] {
            assert!(request(8, 1, &[9], &invalid).is_err());
        }
        for offset in [0, 8, 12 + certificates.len()] {
            let mut invalid = bytes.clone();
            invalid[offset] ^= 0xff;
            assert!(request(8, 1, &[9], &invalid).is_err());
        }
    }
    #[test]
    fn intake_refuses_other_operations_and_unused_authority() {
        assert!(request(1, 0, &[7], &[8]).is_ok());
        assert!(request(1, 1, &[7], &[8]).is_err());
        assert!(request(1, 0, &[7], &[]).is_err());
        assert!(request(1, 0, &[], &[8]).is_err());
        assert_eq!(bounds(1).unwrap(), [10_000, ACCOUNT_MAX]);
        assert!(request(1, 0, &[7], &vec![8; ACCOUNT_MAX + 1]).is_err());
        assert!(request(8, u128::MAX, &[], &[]).is_ok());
        assert!(request(8, 1, &[7], &charge_carrier(&[8], &[9])).is_ok());
        assert!(request(8, 1, &[7], &[8]).is_err());
        assert!(request(8, 1, &[7], &[]).is_err());
        assert!(request(8, 1, &[], &[8]).is_err());
        assert!(request(8, 0, &[], &[]).is_err());
        for selector in [0, 2, 3, 4, 5, 6, 7, 9, u32::MAX] {
            assert!(bounds(selector).is_err());
        }
        assert!(
            request(
                1,
                0,
                &vec![7; KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1 + 1],
                &[8]
            )
            .is_err()
        );
    }
    fn unadmitted_projection_fixture() -> state::NativeOperationReviewV1 {
        use iroha_crypto::{Algorithm, KeyPair};
        use iroha_data_model::account::AccountId;
        let account = AccountId::new(
            KeyPair::from_seed(vec![7; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        let payment = p256::ecdsa::SigningKey::from_bytes((&[9; 32]).into()).unwrap();
        state::NativeOperationReviewV1 {
            kind: KagemushaWalletOperationKindV1::Send,
            amount: 1,
            fee: 2,
            gross_debit: 3,
            net_destination_amount: 1,
            receiver_wallet_id: Some([4; 32]),
            destination_account_digest: kagemusha_wallet_account_digest_v1(&account).unwrap(),
            destination_account_original: Some(norito::encode_canonical(&account).unwrap()),
            request_digest: [5; 32],
            charge_quote_digest: [0; 32],
            scheme_id: [6; 32],
            wallet_id: [7; 32],
            current_head: [8; 32],
            source_state_commitment: [9; 32],
            source_capsule_digest: [10; 32],
            credential_digest: [11; 32],
            payment_key: KagemushaDevicePublicKeyV1::from_sec1_bytes(
                payment.verifying_key().to_encoded_point(false).as_bytes(),
            )
            .unwrap(),
            artifact_manifest_digest: [12; 32],
        }
    }
    #[test]
    fn projection_transports_exact_bounded_original_with_explicit_length() {
        // Public DATA framing only; this fixture cannot construct a genuine reviewed token.
        let value = unadmitted_projection_fixture();
        let original = value.destination_account_original.as_ref().unwrap();
        let bytes = projection(&value).unwrap();
        assert_eq!(bytes.len(), PROJECTION_FIXED_BYTES + original.len());
        assert_eq!(
            &bytes[FINANCIAL_BYTES..PROJECTION_FIXED_BYTES],
            &(original.len() as u32).to_le_bytes()
        );
        assert_eq!(&bytes[PROJECTION_FIXED_BYTES..], original);
        assert_eq!(&bytes[106..138], &value.destination_account_digest);
        let mut copied = bytes;
        copied[PROJECTION_FIXED_BYTES] ^= 1;
        assert_ne!(&copied[PROJECTION_FIXED_BYTES..], original);
        assert_eq!(
            &projection(&value).unwrap()[PROJECTION_FIXED_BYTES..],
            original.as_slice()
        );
    }
    #[test]
    fn projection_rejects_missing_oversized_and_foreign_unload_original_shapes() {
        for original in [None, Some(vec![]), Some(vec![0; ACCOUNT_MAX + 1])] {
            let mut value = unadmitted_projection_fixture();
            value.destination_account_original = original;
            assert_eq!(projection(&value).unwrap_err().status, INTERNAL);
        }
        let mut unload = unadmitted_projection_fixture();
        unload.kind = KagemushaWalletOperationKindV1::Unload;
        unload.receiver_wallet_id = None;
        unload.request_digest = [0; 32];
        assert_eq!(projection(&unload).unwrap_err().status, INTERNAL);
        unload.destination_account_original = None;
        let bytes = projection(&unload).unwrap();
        assert_eq!(bytes.len(), PROJECTION_FIXED_BYTES);
        assert_eq!(&bytes[FINANCIAL_BYTES..], &[0; 4]);
    }
    #[test]
    fn consumed_tokens_never_replay_or_alias_another_review() {
        let mut first = Tokens::default();
        let one = first.put(String::from("opaque-one")).unwrap();
        let two = first.put(String::from("opaque-two")).unwrap();
        assert_eq!(first.take(one).unwrap(), "opaque-one");
        assert!(first.take(one).is_err());
        assert_eq!(first.take(two).unwrap(), "opaque-two");
        assert!(first.put(String::from("later")).unwrap() > two);
        assert!(Tokens::<String>::default().take(one).is_err());
    }
    #[test]
    fn outstanding_reviews_are_bounded_without_reusing_tokens() {
        let mut tokens = Tokens::default();
        let ids: Vec<_> = (0..MAX_REVIEWS).map(|i| tokens.put(i).unwrap()).collect();
        assert!(ids.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(tokens.put(9).unwrap_err().status, RESOURCE);
        assert_eq!(tokens.take(ids[2]).unwrap(), 2);
        assert!(tokens.put(9).unwrap() > *ids.last().unwrap());
        tokens.clear();
        for id in ids {
            assert!(tokens.take(id).is_err());
        }
        assert!(tokens.put(10).is_ok());
        let exhausted = std::sync::atomic::AtomicU64::new(i64::MAX as u64 - 1);
        assert_eq!(allocate_from(&exhausted).unwrap(), i64::MAX as u64);
        assert_eq!(allocate_from(&exhausted).unwrap_err().status, RESOURCE);
        assert_eq!(allocate_from(&exhausted).unwrap_err().status, RESOURCE);
    }
    #[test]
    fn simultaneously_outstanding_owner_and_purpose_tokens_never_alias() {
        let mut a = Tokens::default();
        let mut b = Tokens::default();
        let a_token = a.put("deletion A").unwrap();
        let b_token = b.put("deletion B").unwrap();
        let time = allocate_token().unwrap();
        let mut financial = Tokens::default();
        let financial_token = financial.put("financial").unwrap();
        assert!(b.take(a_token).is_err());
        assert!(a.take(b_token).is_err());
        assert!(a.take(time).is_err());
        assert!(a.take(financial_token).is_err());
        assert_eq!(a.take(a_token).unwrap(), "deletion A");
        assert_eq!(b.take(b_token).unwrap(), "deletion B");
        assert_eq!(financial.take(financial_token).unwrap(), "financial");
    }
    #[test]
    fn raw_send_and_unload_cannot_reach_an_owner_without_review() {
        for action in [
            state::OperationActionV1::Send { request: vec![1] },
            state::OperationActionV1::Unload {
                amount: 1,
                charge: None,
            },
        ] {
            // INVALID is emitted before unknown-handle CLOSED, proving the ordinary
            // foreign execute route cannot reach a Native monetary owner for these actions.
            let error = execute(
                u64::MAX,
                state::OperationRequestV1 {
                    request_id: [1; 32],
                    action,
                },
            )
            .unwrap_err();
            assert_eq!(error.status, INVALID);
        }
    }
    #[test]
    fn invalid_c_review_initializes_every_output_before_refusing() {
        let mut out = WalletResult::default();
        let status =
            unsafe { connect_norito_kagemusha_wallet_review_v1(0, std::ptr::null(), &mut out) };
        assert_eq!(status, INVALID);
        assert_eq!(out.status, INVALID);
        assert_eq!(out.reason, -1);
        assert_eq!(out.sequence_low, 0);
        assert_eq!(out.sequence_high, 0);
        assert_eq!(out.detail, 0);
        assert!(out.bytes.is_null());
        assert_eq!(out.length, 0);
    }
}
