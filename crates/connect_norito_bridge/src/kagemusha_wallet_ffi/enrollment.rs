//! Native enrollment custody followed by complete source-qualified runtime installation.
use super::*;
use iroha_core_zk::kagemusha_wallet_enrollment_v1 as native;

/// Enrollment actions contain originals only; no policy, time, liveness or hardware verdict.
pub(crate) enum Action<'a> {
    Start([&'a [u8]; 3]),
    RenewSession([&'a [u8]; 3]),
    Begin([&'a [u8]; 3]),
    Authorize(&'a [u8]),
    AcceptPermit(&'a [u8]),
    Progress,
    Prepare(native::PlatformEvidenceV1),
    RetainRequest(&'a [u8]),
    AcceptResult(&'a [u8]),
    Load,
    BeginOpen,
    BeginResult([&'a [u8]; 2]),
    AppleOriginals,
    BeginAppleEffect(u8),
    RetainAppleEffect(u8, &'a [u8]),
    RetainedRequest,
    RetainedResult,
    CompleteAppleCollection,
    Abandon,
    AbandonLedgerInstruction,
}
impl From<native::Error> for Failure {
    fn from(error: native::Error) -> Self {
        match error {
            native::Error::Provider(error) => error.into(),
            native::Error::Original(_) => Self::code(INVALID),
            native::Error::Phase => Self::code(CONFLICT),
        }
    }
}
fn response(kind: i32, bytes: Vec<u8>) -> Response {
    Response {
        kind,
        bytes,
        ..Response::default()
    }
}
fn progress(value: native::EnrollmentProgressV1) -> Response {
    match value {
        native::EnrollmentProgressV1::Evidence {
            slot,
            marker,
            challenge_digest,
        } => {
            // Fixed FFI projection, not a wire carrier or an authority verdict.
            let mut bytes = Vec::with_capacity(161);
            bytes.extend_from_slice(&slot);
            bytes.extend_from_slice(marker.payment_key.as_sec1_bytes());
            bytes.extend_from_slice(&challenge_digest);
            bytes.extend_from_slice(&kagemusha_wallet_enrollment_key_binding_v1(
                &challenge_digest,
                &marker.payment_key,
            ));
            response(19, bytes)
        }
        native::EnrollmentProgressV1::Pending => response(20, Vec::new()),
        native::EnrollmentProgressV1::Abandoned => response(21, Vec::new()),
        native::EnrollmentProgressV1::BootstrapSelected => response(22, Vec::new()),
    }
}
/// Design §3.2 abandonment result. The no-marker form is local, has nothing to submit and
/// returns kind 58 with no bytes; the marker form returns kind 28 with the exact retained
/// signed frame, byte for byte on every retry. An empty marker frame is never projected as
/// either form: no outcome may be inferred from it.
pub(super) fn abandonment(value: native::EnrollmentAbandonmentV1) -> Result<Response> {
    match value {
        native::EnrollmentAbandonmentV1::LocalAbandoned => Ok(response(58, Vec::new())),
        native::EnrollmentAbandonmentV1::Abandonment(bytes) if bytes.is_empty() => {
            Err(Failure::code(INTERNAL))
        }
        native::EnrollmentAbandonmentV1::Abandonment(bytes) => Ok(response(28, bytes)),
    }
}
/// Execute against the enrollment phase of the SAME installed runtime.
pub(super) fn perform<F: advance::KagemushaWalletFsV1, P: advance::KagemushaWalletPlatformV1>(
    owner: &mut native::EnrollmentOwnerV1<F, P>,
    action: Action<'_>,
) -> Result<Response> {
    Ok(match action {
        Action::Begin([request_id, account, asset]) => {
            response(27, owner.begin(request_id, account, asset)?)
        }
        Action::AcceptPermit(bytes) => response(18, owner.accept_permit(bytes)?.to_vec()),
        Action::Authorize(signature) => progress(owner.authorize(signature)?),
        Action::Progress => progress(owner.progress()?),
        Action::Prepare(evidence) => {
            let bytes = norito::encode_canonical(&evidence).map_err(|_| Failure::code(INVALID))?;
            match owner.prepare_request(&bytes)? {
                native::RequestPreparationV1::Retained(bytes) => response(24, bytes),
                native::RequestPreparationV1::AccountChallenge(message) => {
                    response(23, message.to_vec())
                }
            }
        }
        Action::RetainRequest(signature) => response(24, owner.retain_request(signature)?),
        Action::AcceptResult(bytes) => response(25, owner.accept_credential(bytes)?),
        Action::RetainedResult => match owner.retained_result()? {
            Some(bytes) => response(25, bytes),
            None => response(20, Vec::new()),
        },
        Action::Abandon => abandonment(owner.abandon()?)?,
        Action::AbandonLedgerInstruction => match owner.abandonment_ledger_instruction()? {
            Some(bytes) => response(59, bytes),
            None => response(58, Vec::new()),
        },
        Action::AppleOriginals => {
            let originals = owner.apple_collection_originals()?;
            let mut bytes = Vec::new();
            for original in originals {
                bytes.extend_from_slice(&(original.len() as u32).to_be_bytes());
                bytes.extend_from_slice(&original);
            }
            response(38, bytes)
        }
        Action::BeginAppleEffect(stage) => {
            owner.begin_apple_effect(stage)?;
            response(39, Vec::new())
        }
        Action::RetainAppleEffect(stage, bytes) => {
            owner.retain_apple_effect(stage, bytes)?;
            response(39, Vec::new())
        }
        Action::CompleteAppleCollection => {
            owner.complete_apple_collection()?;
            response(39, Vec::new())
        }
        Action::RetainedRequest => match owner.retained_request()? {
            Some(bytes) => response(24, bytes),
            None => response(20, Vec::new()),
        },
        Action::Start(_)
        | Action::RenewSession(_)
        | Action::Load
        | Action::BeginOpen
        | Action::BeginResult(_) => {
            return Err(Failure::code(CONFLICT));
        }
    })
}
pub(crate) fn call(id: u64, action: Action<'_>) -> Result<Response> {
    open::enroll(id, action)
}

/// Holder class of one relayed closed E1 refusal code (design §2.4) for evidence of the given
/// platform: 1 Phone, 2 App, 3 Attempt, 4 Account. Native owns the table; Core and the SDKs
/// relay the issuer's `u16` unchanged. Zero, unknown and platform-inapplicable codes are
/// protocol errors, never admission and never a phone verdict.
pub(crate) fn refusal_class(code: u16, android: bool) -> Result<i32> {
    use KagemushaWalletEnrollmentRefusalClassV1 as Class;
    let reason = KagemushaWalletEnrollmentRefusalV1::from_code(code)
        .filter(|reason| reason.applies_to(android))
        .ok_or(Failure::code(INVALID))?;
    Ok(match reason.class() {
        Class::Phone => 1,
        Class::App => 2,
        Class::Attempt => 3,
        Class::Account => 4,
    })
}

pub(crate) fn bounds(selector: u32) -> Result<[usize; 3]> {
    Ok(match selector {
        0 => [32, 4096, 1024],
        1 | 5 => [64, 0, 0],
        2 | 3 | 7 | 8 | 10 => [0; 3],
        4 => [32, 65_536, 4096],
        6 => [native::RESULT_MAX_BYTES, 0, 0],
        9 => [2048, 0, 0],
        11 | 19 => [16_384, 4096, 16_384],
        12 => [native::RESULT_MAX_BYTES, 4096, 0],
        13 | 16 | 17 | 18 | 20 => [0; 3],
        14 => [1, 0, 0],
        15 => [1, 65_536, 0],
        _ => return Err(Failure::code(INVALID)),
    })
}
pub(crate) fn request<'a>(
    selector: u32,
    originals: [&'a [u8]; 3],
    chain: &[&[u8]],
) -> Result<Action<'a>> {
    let limits = bounds(selector)?;
    if originals
        .iter()
        .zip(limits)
        .any(|(bytes, bound)| bytes.len() > bound)
        || (selector != 3 && !chain.is_empty())
        || chain.len() > native::ANDROID_CHAIN_MAX
        || chain
            .iter()
            .any(|item| item.is_empty() || item.len() > native::ANDROID_CERTIFICATE_MAX_BYTES)
        || chain.iter().map(|item| item.len()).sum::<usize>() > native::ANDROID_CHAIN_MAX_BYTES
    {
        return Err(Failure::code(INVALID));
    }
    let [first, second, third] = originals;
    Ok(match selector {
        0 if first.len() == 32 && !second.is_empty() && !third.is_empty() => {
            Action::Begin(originals)
        }
        // The authenticated product selection requires either genuine DPoP (CBSI)
        // or an empty proof frame (BPNG), and the exact selected Apple root DER on Apple or
        // an empty root on Android, whose KeyMint chain carries its own root. This boundary
        // only checks frame bounds.
        11 if !first.is_empty() => Action::Start(originals),
        19 if !first.is_empty() => Action::RenewSession(originals),
        12 if !first.is_empty() && !second.is_empty() => Action::BeginResult([first, second]),
        13 => Action::AppleOriginals,
        14 if first.len() == 1 && (1..=3).contains(&first[0]) => Action::BeginAppleEffect(first[0]),
        15 if first.len() == 1 && (1..=3).contains(&first[0]) && !second.is_empty() => {
            Action::RetainAppleEffect(first[0], second)
        }
        16 => Action::RetainedRequest,
        18 => Action::RetainedResult,
        17 => Action::CompleteAppleCollection,
        1 => Action::Authorize(first),
        2 => Action::Progress,
        // The leaf-first KeyMint chain is the whole Android evidence: no token or verdict.
        3 if chain.len() >= native::ANDROID_CHAIN_MIN => {
            Action::Prepare(native::PlatformEvidenceV1::Android {
                certificates: chain.iter().map(|item| item.to_vec()).collect(),
            })
        }
        4 if first.len() == 32 && !second.is_empty() && !third.is_empty() => {
            Action::Prepare(native::PlatformEvidenceV1::Apple {
                key_id: first.try_into().map_err(|_| Failure::code(INVALID))?,
                attestation: second.to_vec(),
                key_binding_assertion: third.to_vec(),
            })
        }
        5 => Action::RetainRequest(first),
        6 if !first.is_empty() => Action::AcceptResult(first),
        7 => Action::Load,
        8 => Action::BeginOpen,
        10 => Action::Abandon,
        20 => Action::AbandonLedgerInstruction,
        9 if !first.is_empty() => Action::AcceptPermit(first),
        _ => return Err(Failure::code(INVALID)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn abandonment_ledger_instruction_accepts_no_foreign_original_or_chain() {
        assert!(matches!(
            request(20, [&[], &[], &[]], &[]).unwrap(),
            Action::AbandonLedgerInstruction
        ));
        for originals in [
            [&[1][..], &[][..], &[][..]],
            [&[][..], &[1][..], &[][..]],
            [&[][..], &[][..], &[1][..]],
        ] {
            assert!(request(20, originals, &[]).is_err());
        }
        assert!(request(20, [&[], &[], &[]], &[&[1]]).is_err());
    }
    #[test]
    fn abandonment_results_are_explicit_and_exact_through_the_c_result() {
        use native::EnrollmentAbandonmentV1 as A;
        let frame = vec![0x5a, 0, 0xff, 7, 0];
        // Marker form: kind 28 with the exact retained frame on every retry.
        for _ in 0..3 {
            let mut out = WalletResult::default();
            let status = unsafe {
                super::super::exports::output(&mut out, || {
                    abandonment(A::Abandonment(frame.clone()))
                })
            };
            assert_eq!((status, out.status, out.reason, out.detail), (0, 28, -1, 0));
            assert_eq!(
                unsafe { std::slice::from_raw_parts(out.bytes, out.length) },
                frame.as_slice()
            );
            crate::connect_norito_free(out.bytes);
        }
        // No-marker form: kind 58, null bytes, length 0; nothing to submit.
        for _ in 0..2 {
            let mut out = WalletResult::default();
            let status = unsafe {
                super::super::exports::output(&mut out, || abandonment(A::LocalAbandoned))
            };
            assert_eq!((status, out.status, out.length), (0, 58, 0));
            assert!(out.bytes.is_null());
        }
        // Kind 58 is distinct from every earlier result kind, including EpochProgress 57.
        assert_eq!(abandonment(A::LocalAbandoned).unwrap().kind, 58);
        assert!(abandonment(A::LocalAbandoned).unwrap().bytes.is_empty());
        assert_eq!(
            abandonment(A::Abandonment(Vec::new())).unwrap_err(),
            Failure::code(INTERNAL)
        );
    }
    #[test]
    fn original_enrollment_bounds_are_per_role_and_unused_fields_are_rejected() {
        for selector in 0..=20 {
            let limits = bounds(selector).unwrap();
            for slot in 0..3 {
                let long = vec![0; limits[slot] + 1];
                let mut originals = [&[][..]; 3];
                originals[slot] = &long;
                assert!(request(selector, originals, &[]).is_err());
            }
        }
        assert!(request(21, [&[]; 3], &[]).is_err());
        assert!(request(19, [&[]; 3], &[]).is_err());
        assert!(matches!(
            request(19, [b"JWT", b"DPoP", b"root"], &[]).unwrap(),
            Action::RenewSession(_)
        ));
        assert!(matches!(
            request(19, [b"JWT", &[], b"root"], &[]).unwrap(),
            Action::RenewSession(_)
        ));
        assert!(matches!(
            request(16, [&[]; 3], &[]).unwrap(),
            Action::RetainedRequest
        ));
        assert!(matches!(
            request(18, [&[]; 3], &[]).unwrap(),
            Action::RetainedResult
        ));
        for selector in [16, 18] {
            assert_eq!(bounds(selector).unwrap(), [0; 3]);
            assert!(request(selector, [&[]; 3], &[b"foreign chain"]).is_err());
        }
        assert!(request(12, [b"result", b"account", &[]], &[]).is_ok());
        assert!(request(12, [b"result", &[], &[]], &[]).is_err());
        assert!(request(2, [&[]; 3], &[b"foreign chain"]).is_err());
        // Android evidence is the KeyMint chain only: no token or other original rides along.
        assert_eq!(bounds(3).unwrap(), [0; 3]);
        assert!(request(3, [&[]; 3], &[b"leaf"]).is_err());
        assert!(request(3, [b"token", &[], &[]], &[b"leaf", b"ca"]).is_err());
        assert!(matches!(
            request(3, [&[]; 3], &[b"leaf", b"ca"]).unwrap(),
            Action::Prepare(native::PlatformEvidenceV1::Android { certificates })
                if certificates == [b"leaf".to_vec(), b"ca".to_vec()]
        ));
        let item = vec![7; native::ANDROID_CERTIFICATE_MAX_BYTES];
        let full: Vec<&[u8]> = vec![&item[..]; native::ANDROID_CHAIN_MAX];
        // Eight maximal items exceed the total chain bound before any native decode.
        assert!(request(3, [&[]; 3], &full).is_err());
        let fitting: Vec<&[u8]> = vec![
            &item[..];
            native::ANDROID_CHAIN_MAX_BYTES
                / native::ANDROID_CERTIFICATE_MAX_BYTES
        ];
        assert!(request(3, [&[]; 3], &fitting).is_ok());
        let nine: Vec<&[u8]> = vec![b"c"; native::ANDROID_CHAIN_MAX + 1];
        assert!(request(3, [&[]; 3], &nine).is_err());
        let oversized = vec![7; native::ANDROID_CERTIFICATE_MAX_BYTES + 1];
        assert!(request(3, [&[]; 3], &[b"leaf", &oversized]).is_err());
        assert!(request(3, [&[]; 3], &[b"leaf", b""]).is_err());
        // Session originals: Android supplies no root (its chain carries one); the product
        // selection, not this frame boundary, decides which roots are required.
        for selector in [11, 19] {
            assert!(request(selector, [b"JWT", &[], &[]], &[]).is_ok());
            assert!(request(selector, [&[], &[], b"root"], &[]).is_err());
        }
        assert!(request(4, [&[1; 32], b"attestation", b"assertion"], &[]).is_ok());
        assert!(request(4, [&[1; 32], b"attestation", &vec![0; 4097]], &[]).is_err());
    }
    #[test]
    fn refusal_codes_are_the_closed_native_table_per_platform() {
        let expected = [
            (1, Some(1), None),
            (2, Some(1), None),
            (3, Some(1), None),
            (4, Some(1), None),
            (5, Some(1), Some(1)),
            (6, Some(1), None),
            (7, Some(2), Some(2)),
            (8, Some(2), None),
            (9, Some(3), Some(3)),
            (10, Some(3), Some(3)),
            (11, Some(4), Some(4)),
            (12, Some(4), Some(4)),
        ];
        for (code, android, apple) in expected {
            assert_eq!(refusal_class(code, true).ok(), android, "android {code}");
            assert_eq!(refusal_class(code, false).ok(), apple, "apple {code}");
        }
        for code in [0, 13, 255, u16::MAX] {
            for android in [true, false] {
                assert_eq!(refusal_class(code, android).unwrap_err().status, INVALID);
            }
        }
        // Platform-inapplicable codes are protocol errors, never a softer class.
        assert_eq!(refusal_class(1, false).unwrap_err().status, INVALID);
        assert_eq!(
            connect_norito_kagemusha_wallet_enrollment_refusal_v1(5, 0),
            1
        );
        assert_eq!(
            connect_norito_kagemusha_wallet_enrollment_refusal_v1(8, 1),
            2
        );
        assert_eq!(
            connect_norito_kagemusha_wallet_enrollment_refusal_v1(8, 0),
            INVALID
        );
        assert_eq!(
            connect_norito_kagemusha_wallet_enrollment_refusal_v1(0, 1),
            INVALID
        );
        // The platform flag is exactly 0 (Apple) or 1 (Android).
        assert_eq!(
            connect_norito_kagemusha_wallet_enrollment_refusal_v1(9, 2),
            INVALID
        );
    }
    #[test]
    fn enrollment_ffi_layout_has_no_hidden_original_or_authority_fields() {
        use std::mem::{align_of, offset_of, size_of};
        let pointer = size_of::<usize>();
        let first = (size_of::<u32>() + pointer - 1) & !(pointer - 1);
        assert_eq!(offset_of!(WalletEnrollmentRequest, selector), 0);
        assert_eq!(offset_of!(WalletEnrollmentRequest, first), first);
        assert_eq!(
            offset_of!(WalletEnrollmentRequest, first_length),
            first + pointer
        );
        assert_eq!(
            offset_of!(WalletEnrollmentRequest, second),
            first + 2 * pointer
        );
        assert_eq!(
            offset_of!(WalletEnrollmentRequest, second_length),
            first + 3 * pointer
        );
        assert_eq!(
            offset_of!(WalletEnrollmentRequest, third),
            first + 4 * pointer
        );
        assert_eq!(
            offset_of!(WalletEnrollmentRequest, third_length),
            first + 5 * pointer
        );
        assert_eq!(
            offset_of!(WalletEnrollmentRequest, certificates),
            first + 6 * pointer
        );
        assert_eq!(
            offset_of!(WalletEnrollmentRequest, certificate_count),
            first + 7 * pointer
        );
        assert_eq!(size_of::<WalletEnrollmentRequest>(), first + 8 * pointer);
        assert_eq!(align_of::<WalletEnrollmentRequest>(), pointer);
        assert_eq!(offset_of!(WalletEnrollmentItem, bytes), 0);
        assert_eq!(offset_of!(WalletEnrollmentItem, length), pointer);
        assert_eq!(size_of::<WalletEnrollmentItem>(), 2 * pointer);
    }
    #[test]
    fn c_enrollment_rejects_lengths_before_dereferencing_and_initializes_outputs() {
        let mut input = WalletEnrollmentRequest {
            selector: 3,
            first: std::ptr::null(),
            first_length: 1,
            second: std::ptr::null(),
            second_length: 0,
            third: std::ptr::null(),
            third_length: 0,
            certificates: std::ptr::null(),
            certificate_count: 9,
        };
        let mut output = WalletResult::default();
        assert_eq!(
            unsafe { connect_norito_kagemusha_wallet_enrollment_v1(u64::MAX, &input, &mut output) },
            INVALID
        );
        assert_eq!(output.status, INVALID);
        assert!(output.bytes.is_null());
        assert_eq!(output.length, 0);
        input.selector = 2;
        input.first_length = 0;
        input.certificate_count = 0;
        assert_eq!(
            unsafe { connect_norito_kagemusha_wallet_enrollment_v1(u64::MAX, &input, &mut output) },
            ARTIFACTS_UNAVAILABLE
        );
        assert_eq!(output.status, ARTIFACTS_UNAVAILABLE);
    }
}
