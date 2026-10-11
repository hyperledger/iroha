//! Digest roles, preimages, transcripts and signature freezing.

use std::collections::BTreeSet;

use p256::ecdsa::{Signature as P256Signature, SigningKey, signature::Signer as _};
use sha2::{Digest as _, Sha256};

use super::*;

/// Exact role labels in declaration order. The values a step relation computes or opens
/// (`credit_id`, `proof_digest`, the Payment digest, the blacklist and quota-window trees) are
/// Poseidon values, not SHA roles (owner answers Q1, Q2 and Q9).
const ROLE_LABELS: [&str; 34] = [
    "scheme",
    "relation",
    "provider-contract",
    "asset-scope",
    "account",
    "enrollment-challenge",
    "enrollment-id",
    "enrollment-key-binding",
    "wallet-id",
    "certificate",
    "certificate-set",
    "credential",
    "scheme-policy",
    "fee-schedule",
    "blacklist",
    "quota-share",
    "time-anchor",
    "request",
    "statement",
    "receipt",
    "package",
    "operation-id",
    "output",
    "capsule",
    "marker",
    "completion",
    "fold",
    "voucher",
    "unload-nullifier",
    "renewal-assertion",
    "artifact-manifest",
    "verifying-key-set",
    "charge-quote",
    "evidence",
];

/// P-256 group order `n`.
const ORDER: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
/// `floor(n / 2)`, the largest accepted `s`.
const HALF_ORDER: &str = "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8";

fn bytes32(hex_text: &str) -> [u8; 32] {
    let mut out = [0; 32];
    out.copy_from_slice(&hex::decode(hex_text).expect("hex"));
    out
}

fn sub_be(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0; 32];
    let mut borrow = 0_i16;
    for index in (0..32).rev() {
        let mut value = i16::from(a[index]) - i16::from(b[index]) - borrow;
        borrow = 0;
        if value < 0 {
            value += 256;
            borrow = 1;
        }
        out[index] = u8::try_from(value).expect("byte");
    }
    assert_eq!(borrow, 0, "a >= b");
    out
}

fn raw(r: &[u8; 32], s: &[u8; 32]) -> [u8; 64] {
    let mut out = [0; 64];
    out[..32].copy_from_slice(r);
    out[32..].copy_from_slice(s);
    out
}

fn key(seed: u8) -> (SigningKey, KagemushaDevicePublicKeyV1) {
    let signing = SigningKey::from_bytes((&[seed; 32]).into()).expect("fixed scalar");
    let public = KagemushaDevicePublicKeyV1::from_sec1_bytes(
        signing.verifying_key().to_encoded_point(false).as_bytes(),
    )
    .expect("canonical key");
    (signing, public)
}

fn sign(signing: &SigningKey, message: &[u8; 32]) -> P256Signature {
    signing.sign(message)
}

/// Independent test oracle for the retained H transcript; no public signing/preimage API.
fn hash_transcript(role: KagemushaWalletDigestRoleV1, body: &[u8]) -> Vec<u8> {
    let mut bytes = KAGEMUSHA_WALLET_DIGEST_PREFIX_V1.to_vec();
    bytes.extend_from_slice(role.as_str().as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(
        &u64::try_from(body.len())
            .expect("body length")
            .to_le_bytes(),
    );
    bytes.extend_from_slice(body);
    bytes
}

fn low_and_high(signature: &P256Signature) -> ([u8; 64], [u8; 64]) {
    let bytes = signature.to_bytes();
    let mut r = [0; 32];
    let mut s = [0; 32];
    r.copy_from_slice(&bytes[..32]);
    s.copy_from_slice(&bytes[32..]);
    let twin = sub_be(&bytes32(ORDER), &s);
    if s <= bytes32(HALF_ORDER) {
        (raw(&r, &s), raw(&r, &twin))
    } else {
        (raw(&r, &twin), raw(&r, &s))
    }
}

#[test]
fn kagemusha_wallet_v1_role_labels_are_pinned_unique_and_ascii() {
    assert_eq!(KagemushaWalletDigestRoleV1::ALL.len(), ROLE_LABELS.len());
    let mut seen = BTreeSet::new();
    for (role, label) in KagemushaWalletDigestRoleV1::ALL.iter().zip(ROLE_LABELS) {
        assert_eq!(role.as_str(), label);
        assert!(seen.insert(format!("{role:?}")), "duplicate role {label}");
        assert!(
            label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'-'),
            "{label}"
        );
    }
    let labels: BTreeSet<&str> = ROLE_LABELS.into_iter().collect();
    assert_eq!(labels.len(), ROLE_LABELS.len());
    assert!(!labels.contains("policy-chunk"), "C3 drops policy-chunk");
    // The superseded SHA roles of the Poseidon values are gone, not aliased.
    for label in [
        "credit",
        "proof",
        "step-proof",
        "payment",
        "blacklist-leaf",
        "blacklist-node",
        "quota-window",
        "quota-node",
        "certificate-body",
        "credential-body",
        "renewal-challenge",
        "renewal-key-binding",
        "lineage",
        "credit-opening",
        "credit-status",
        "credited",
    ] {
        assert!(!labels.contains(label), "{label}");
    }
    assert_eq!(
        KAGEMUSHA_WALLET_DIGEST_PREFIX_V1,
        b"iroha:kagemusha:wallet:v1:"
    );
}

#[test]
fn kagemusha_wallet_v1_preimage_layout_and_pinned_digests() {
    let empty = hash_transcript(KagemushaWalletDigestRoleV1::Scheme, &[]);
    assert_eq!(
        hex::encode(&empty),
        "69726f68613a6b6167656d757368613a77616c6c65743a76313a736368656d65000000000000000000"
    );
    assert_eq!(
        hex::encode(kagemusha_wallet_digest_v1(
            KagemushaWalletDigestRoleV1::Scheme,
            &[]
        )),
        "90882608a8e8892521a2661be1e81c3fbfca0f8773e621000daed362a37485a5"
    );
    let body = [0_u8, 1, 2, 3];
    let credential = hash_transcript(KagemushaWalletDigestRoleV1::Credential, &body);
    assert_eq!(
        hex::encode(&credential),
        "69726f68613a6b6167656d757368613a77616c6c65743a76313a63726564656e7469616c000400000000000000\
         00010203"
    );
    assert_eq!(
        hex::encode(kagemusha_wallet_digest_v1(
            KagemushaWalletDigestRoleV1::Credential,
            &body
        )),
        "ce04890831ccf922d21886e0c51ca341b7ec7652a63618aab1921315924ed8ea"
    );
    let mut digests = BTreeSet::new();
    for role in KagemushaWalletDigestRoleV1::ALL {
        let preimage = hash_transcript(role, &body);
        let label = role.as_str().as_bytes();
        let prefix = KAGEMUSHA_WALLET_DIGEST_PREFIX_V1.len();
        assert_eq!(&preimage[..prefix], KAGEMUSHA_WALLET_DIGEST_PREFIX_V1);
        assert_eq!(&preimage[prefix..prefix + label.len()], label);
        assert_eq!(preimage[prefix + label.len()], 0);
        assert_eq!(
            &preimage[prefix + label.len() + 1..prefix + label.len() + 9],
            &4_u64.to_le_bytes()
        );
        assert_eq!(&preimage[prefix + label.len() + 9..], &body);
        let digest = kagemusha_wallet_digest_v1(role, &body);
        assert_eq!(digest, <[u8; 32]>::from(Sha256::digest(&preimage)));
        assert!(digests.insert(digest), "role {} collides", role.as_str());
    }
}

#[test]
fn kagemusha_wallet_v1_signed_object_digest_hashes_body_digest_then_signature() {
    let (signing, _) = key(7);
    let domain = KagemushaWalletSigningDomainV1::Certificate;
    let transcript = vec![0x42; domain.transcript_bytes()];
    let e = kagemusha_wallet_signing_message_v1(domain, &transcript);
    let (low, _) = low_and_high(&sign(&signing, &e));
    let signature = KagemushaDeviceSignatureV1::from_raw_bytes(&low).expect("low-S");
    let mut body = e.to_vec();
    body.extend_from_slice(&low);
    assert_eq!(
        body.len(),
        KAGEMUSHA_WALLET_SIGNED_OBJECT_TRANSCRIPT_BYTES_V1
    );
    assert_eq!(
        kagemusha_wallet_signed_object_digest_v1(
            KagemushaWalletDigestRoleV1::Certificate,
            &e,
            &signature
        ),
        kagemusha_wallet_digest_v1(KagemushaWalletDigestRoleV1::Certificate, &body)
    );
}

#[test]
fn kagemusha_wallet_v1_transcript_builder_writes_fixed_widths() {
    let (signing, public) = key(9);
    let (low, _) = low_and_high(&sign(&signing, &[0x78; 32]));
    let signature = KagemushaDeviceSignatureV1::from_raw_bytes(&low).expect("low-S");
    let transcript = WalletTranscriptV1::with_capacity(0)
        .u8(0xab)
        .u16(0x0102)
        .u32(0x0304_0506)
        .u64(0x0708_090a_0b0c_0d0e)
        .digest(&[0x11; 32])
        .key(&public)
        .signature(&signature)
        .bytes(&[0xee, 0xff])
        .finish();
    let mut expected = vec![0xab, 0x02, 0x01, 0x06, 0x05, 0x04, 0x03];
    expected.extend_from_slice(&0x0708_090a_0b0c_0d0e_u64.to_le_bytes());
    expected.extend_from_slice(&[0x11; 32]);
    expected.extend_from_slice(public.as_sec1_bytes());
    expected.extend_from_slice(&low);
    expected.extend_from_slice(&[0xee, 0xff]);
    assert_eq!(transcript, expected);
    assert_eq!(transcript.len(), 1 + 2 + 4 + 8 + 32 + 65 + 64 + 2);

    let wide = WalletTranscriptV1::with_capacity(0)
        .u128(0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10)
        .zeros(3)
        .u8(0x7f)
        .finish();
    let mut expected = 0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10_u128
        .to_le_bytes()
        .to_vec();
    expected.extend_from_slice(&[0, 0, 0, 0x7f]);
    assert_eq!(wide, expected);
}

#[test]
fn kagemusha_wallet_v1_freeze_normalizes_der_and_raw_high_s() {
    let (signing, public) = key(7);
    let role = KagemushaWalletSigningDomainV1::Credential;
    let body = kagemusha_wallet_signing_message_v1(role, &vec![0x43; role.transcript_bytes()]);
    let signature = sign(&signing, &body);
    let (low, high) = low_and_high(&signature);
    let der = signature.to_der();
    for output in [
        KagemushaWalletSignerOutputV1::Raw(low),
        KagemushaWalletSignerOutputV1::Raw(high),
        KagemushaWalletSignerOutputV1::Der(der.as_bytes()),
    ] {
        let frozen =
            kagemusha_wallet_freeze_signature_v1(&public, role, &body, output).expect("freeze");
        assert_eq!(frozen.as_raw_bytes(), &low);
        kagemusha_wallet_verify_signature_v1(&public, role, &body, &frozen).expect("verify");
    }
    let high_der = P256Signature::from_slice(&high).expect("high twin parses");
    let frozen = kagemusha_wallet_freeze_signature_v1(
        &public,
        role,
        &body,
        KagemushaWalletSignerOutputV1::Der(high_der.to_der().as_bytes()),
    )
    .expect("freeze high-S DER");
    assert_eq!(frozen.as_raw_bytes(), &low);
}

#[test]
fn kagemusha_wallet_v1_freeze_rejects_invalid_or_unbound_output() {
    let (signing, public) = key(7);
    let (_, other) = key(8);
    let role = KagemushaWalletSigningDomainV1::Request;
    let body = kagemusha_wallet_signing_message_v1(role, &vec![0x44; role.transcript_bytes()]);
    let signature = sign(&signing, &body);
    let (low, _) = low_and_high(&signature);
    let rejected =
        |result: Result<KagemushaDeviceSignatureV1, KagemushaWalletValidationErrorV1>| {
            matches!(
                result,
                Err(KagemushaWalletValidationErrorV1::InvalidSignature { .. })
            )
        };
    let raw_output = KagemushaWalletSignerOutputV1::Raw(low);
    assert!(rejected(kagemusha_wallet_freeze_signature_v1(
        &other, role, &body, raw_output
    )));
    assert!(rejected(kagemusha_wallet_freeze_signature_v1(
        &public,
        KagemushaWalletSigningDomainV1::Offer,
        &kagemusha_wallet_signing_message_v1(KagemushaWalletSigningDomainV1::Offer, &[0x44; 194]),
        raw_output
    )));
    assert!(rejected(kagemusha_wallet_freeze_signature_v1(
        &public,
        role,
        &kagemusha_wallet_signing_message_v1(role, &vec![0x46; role.transcript_bytes()]),
        raw_output
    )));
    let mut der = signature.to_der().as_bytes().to_vec();
    der.push(0);
    assert!(rejected(kagemusha_wallet_freeze_signature_v1(
        &public,
        role,
        &body,
        KagemushaWalletSignerOutputV1::Der(&der)
    )));
    let order = bytes32(ORDER);
    let one = {
        let mut one = [0; 32];
        one[31] = 1;
        one
    };
    for invalid in [
        raw(&[0; 32], &one),
        raw(&one, &[0; 32]),
        raw(&order, &one),
        raw(&one, &order),
    ] {
        assert!(rejected(kagemusha_wallet_freeze_signature_v1(
            &public,
            role,
            &body,
            KagemushaWalletSignerOutputV1::Raw(invalid)
        )));
    }
}

#[test]
fn kagemusha_wallet_v1_verify_rejects_high_s_and_wrong_bindings() {
    let (signing, public) = key(7);
    let (_, other) = key(8);
    let role = KagemushaWalletSigningDomainV1::Receipt;
    let body = kagemusha_wallet_signing_message_v1(role, &vec![0x45; role.transcript_bytes()]);
    let (low, high) = low_and_high(&sign(&signing, &body));
    assert!(KagemushaDeviceSignatureV1::from_raw_bytes(&high).is_err());
    let signature = KagemushaDeviceSignatureV1::from_raw_bytes(&low).expect("low-S");
    assert!(kagemusha_wallet_verify_signature_v1(&public, role, &body, &signature).is_ok());
    for (key, role, body) in [
        (&other, role, body),
        (
            &public,
            KagemushaWalletSigningDomainV1::Certificate,
            kagemusha_wallet_signing_message_v1(
                KagemushaWalletSigningDomainV1::Certificate,
                &[0x45; 108],
            ),
        ),
        (
            &public,
            role,
            kagemusha_wallet_signing_message_v1(role, &vec![0x46; role.transcript_bytes()]),
        ),
    ] {
        assert!(matches!(
            kagemusha_wallet_verify_signature_v1(key, role, &body, &signature),
            Err(KagemushaWalletValidationErrorV1::InvalidSignature { .. })
        ));
    }
}

#[test]
fn kagemusha_wallet_v1_signature_boundary_scalars() {
    let order = bytes32(ORDER);
    let half = bytes32(HALF_ORDER);
    let mut one = [0; 32];
    one[31] = 1;
    let half_plus_one = sub_be(&order, &half);
    assert_eq!(
        hex::encode(half_plus_one),
        "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a9"
    );
    assert!(KagemushaDeviceSignatureV1::from_raw_bytes(&raw(&one, &half)).is_ok());
    for rejected in [
        raw(&one, &half_plus_one),
        raw(&one, &sub_be(&order, &one)),
        raw(&[0; 32], &one),
        raw(&one, &[0; 32]),
        raw(&order, &one),
        raw(&one, &order),
    ] {
        assert!(KagemushaDeviceSignatureV1::from_raw_bytes(&rejected).is_err());
    }
    // A high scalar is normalized to its low twin before verification; an arbitrary pair
    // still fails verification rather than being accepted.
    let (_, public) = key(7);
    assert!(matches!(
        kagemusha_wallet_freeze_signature_v1(
            &public,
            KagemushaWalletSigningDomainV1::Receipt,
            &[0; 32],
            KagemushaWalletSignerOutputV1::Raw(raw(&one, &half_plus_one))
        ),
        Err(KagemushaWalletValidationErrorV1::InvalidSignature {
            domain: KagemushaWalletSigningDomainV1::Receipt
        })
    ));
}

#[test]
fn kagemusha_wallet_v1_signing_domains_are_exact_and_messages_use_poseidon() {
    let labels = [
        "kgwcert1", "kgwcred1", "kgwrnch1", "kgwrnkb1", "kgwartf1", "kgwrcpt1", "kgwspol1",
        "kgwfsch1", "kgwblst1", "kgwqshr1", "kgwtanc1", "kgwchgq1", "kgwoffr1", "kgwsctl1",
        "kgwrqst1", "kgwvchr1", "kgwlctl1",
    ];
    let lengths = [
        108, 476, 130, 163, 290, 338, 142, 191, 118, 190, 138, 219, 194, 197, 418, 250, 211,
    ];
    let mut seen = BTreeSet::new();
    for ((domain, label), length) in KagemushaWalletSigningDomainV1::ALL
        .into_iter()
        .zip(labels)
        .zip(lengths)
    {
        assert_eq!(domain.as_str(), label);
        assert_eq!(domain.transcript_bytes(), length);
        assert_eq!(
            domain.domain().to_le_bytes(),
            *label.as_bytes().first_chunk::<8>().expect("domain")
        );
        let transcript = vec![0x47; length];
        let message = kagemusha_wallet_signing_message_v1(domain, &transcript);
        assert_eq!(message.len(), 32);
        assert_eq!(
            message,
            super::super::poseidon::kagemusha_wallet_poseidon_bytes_v1(
                domain.domain(),
                &transcript
            )
        );
        assert!(kagemusha_wallet_is_canonical_field_v1(&message));
        assert!(seen.insert(message));
    }
}
