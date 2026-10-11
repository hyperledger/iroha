//! Digest roles, preimages, signing domains and messages, transcripts and signature freezing.

use std::collections::BTreeSet;

use p256::ecdsa::{
    Signature as P256Signature, SigningKey,
    signature::{Signer as _, hazmat::PrehashSigner as _},
};
use sha2::{Digest as _, Sha256};

use super::*;
use crate::kagemusha::kagemusha_wallet_v1::poseidon::{
    KAGEMUSHA_WALLET_POSEIDON_DOMAINS_V1, kagemusha_wallet_poseidon_bytes_v1,
};

/// Exact role labels in declaration order. Every digest a relation recomputes (`credit_id`,
/// `proof_digest`, the statement, object, certificate-set, package, operation, nullifier,
/// Payment, lineage, credit-opening, credit-status and credited digests, every signing message,
/// the trees and the quota-usage array) is a Poseidon value, not a SHA role (owner answers Q1,
/// Q2, Q9, A1, A3 and B1).
const ROLE_LABELS: [&str; 20] = [
    "scheme",
    "relation",
    "provider-contract",
    "asset-scope",
    "account",
    "enrollment-challenge",
    "app-policy",
    "enrollment-policy",
    "enrollment-id",
    "enrollment-key-binding",
    "wallet-id",
    "artifact-manifest",
    "evidence",
    "renewal-assertion",
    "verifying-key-set",
    "output",
    "marker",
    "capsule",
    "completion",
    "fold",
];

/// Object-digest domains in declaration order with the signing domain of their body (wire
/// record §1, owner answer B1).
const OBJECT_DOMAINS: [(&str, &str); 10] = [
    ("kgwocrt1", "kgwcert1"),
    ("kgwocrd1", "kgwcred1"),
    ("kgworcp1", "kgwrcpt1"),
    ("kgwopol1", "kgwspol1"),
    ("kgwofee1", "kgwfsch1"),
    ("kgwoblk1", "kgwblst1"),
    ("kgwoqsh1", "kgwqshr1"),
    ("kgwotim1", "kgwtanc1"),
    ("kgwochg1", "kgwchgq1"),
    ("kgworeq1", "kgwrqst1"),
];

/// Signing domains in declaration order with their exact transcript lengths (wire record §1).
const SIGNING_DOMAINS: [(&str, usize); 16] = [
    ("kgwcert1", 108),
    ("kgwcred1", 476),
    ("kgwrnch1", 130),
    ("kgwrnkb1", 163),
    ("kgwartf1", 290),
    ("kgwrcpt1", 338),
    ("kgwspol1", 142),
    ("kgwfsch1", 191),
    ("kgwblst1", 118),
    ("kgwqshr1", 190),
    ("kgwtanc1", 138),
    ("kgwchgq1", 219),
    ("kgwoffr1", 194),
    ("kgwsctl1", 197),
    ("kgwrqst1", 458),
    ("kgwlctl1", 211),
];

/// Exact SHA-256 preimage of `H(role, body)`: `prefix || role || 0x00 || LE64 len || body`.
fn preimage(role: KagemushaWalletDigestRoleV1, body: &[u8]) -> Vec<u8> {
    let mut preimage = KAGEMUSHA_WALLET_DIGEST_PREFIX_V1.to_vec();
    preimage.extend_from_slice(role.as_str().as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(&u64::try_from(body.len()).expect("length").to_le_bytes());
    preimage.extend_from_slice(body);
    preimage
}

/// A transcript of the exact length of `domain`, filled with `fill`.
fn transcript(domain: KagemushaWalletSigningDomainV1, fill: u8) -> Vec<u8> {
    vec![fill; domain.transcript_bytes()]
}

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

/// RFC 6979 ECDSA-P256-SHA256 signature over the 32-byte signing message `m`.
fn sign(signing: &SigningKey, message: &[u8; 32]) -> P256Signature {
    signing.sign(message)
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
    // The superseded SHA roles of the Poseidon values and every signed-body role are gone, not
    // aliased (owner answers A1, A3 and B1).
    for label in [
        "certificate",
        "certificate-set",
        "credential",
        "receipt",
        "scheme-policy",
        "fee-schedule",
        "blacklist",
        "quota-share",
        "time-anchor",
        "charge-quote",
        "request",
        "voucher",
        "statement",
        "package",
        "operation-id",
        "unload-nullifier",
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
        "scheme-policy-body",
        "fee-schedule-body",
        "blacklist-body",
        "quota-share-body",
        "time-anchor-body",
        "offer-body",
        "session-control-body",
        "request-body",
        "receipt-body",
        "voucher-body",
        "ledger-control-body",
        "renewal-challenge",
        "renewal-key-binding",
        "artifact-manifest-body",
        "charge-quote-body",
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
    let empty = preimage(KagemushaWalletDigestRoleV1::Scheme, &[]);
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
    let evidence = preimage(KagemushaWalletDigestRoleV1::Evidence, &body);
    assert_eq!(
        hex::encode(&evidence),
        "69726f68613a6b6167656d757368613a77616c6c65743a76313a65766964656e636500040000000000000000\
         010203"
    );
    assert_eq!(
        hex::encode(kagemusha_wallet_digest_v1(
            KagemushaWalletDigestRoleV1::Evidence,
            &body
        )),
        "3e1c77a6bd8e359af7958b5a614a5fdddf96d6763ebf2e0988bda2c0ab9ea026"
    );
    let mut digests = BTreeSet::new();
    for role in KagemushaWalletDigestRoleV1::ALL {
        let digest = kagemusha_wallet_digest_v1(role, &body);
        assert_eq!(
            digest,
            <[u8; 32]>::from(Sha256::digest(preimage(role, &body)))
        );
        assert!(digests.insert(digest), "role {} collides", role.as_str());
    }
}

#[test]
fn kagemusha_wallet_v1_signing_domains_are_pinned_and_distinct() {
    assert_eq!(
        KagemushaWalletSigningDomainV1::ALL.len(),
        SIGNING_DOMAINS.len()
    );
    let mut words = BTreeSet::new();
    for (domain, (label, bytes)) in KagemushaWalletSigningDomainV1::ALL
        .iter()
        .zip(SIGNING_DOMAINS)
    {
        assert_eq!(domain.as_str(), label);
        assert_eq!(&domain.ascii(), label.as_bytes());
        assert_eq!(domain.domain(), u64::from_le_bytes(domain.ascii()));
        assert_eq!(domain.transcript_bytes(), bytes, "{label}");
        assert!(words.insert(domain.domain()), "{label}");
    }
    // No signing domain reuses a non-signing Poseidon domain.
    for (name, domain) in KAGEMUSHA_WALLET_POSEIDON_DOMAINS_V1 {
        assert!(words.insert(domain), "{name}");
    }
    for domain in KagemushaWalletObjectDigestDomainV1::ALL {
        assert!(words.insert(domain.domain()), "{}", domain.as_str());
    }
    assert_eq!(words.len(), 59);
}

#[test]
fn kagemusha_wallet_v1_signing_message_is_the_packed_poseidon_digest() {
    let mut messages = BTreeSet::new();
    for domain in KagemushaWalletSigningDomainV1::ALL {
        let body = transcript(domain, 0x5a);
        let message = kagemusha_wallet_signing_message_v1(domain, &body);
        assert_eq!(
            message,
            kagemusha_wallet_poseidon_bytes_v1(domain.domain(), &body)
        );
        assert!(kagemusha_wallet_is_canonical_field_v1(&message));
        assert!(messages.insert(message), "{}", domain.as_str());
        // One byte of the transcript changes the message.
        let mut tampered = body.clone();
        tampered[domain.transcript_bytes() - 1] ^= 1;
        assert_ne!(
            kagemusha_wallet_signing_message_v1(domain, &tampered),
            message
        );
    }
}

#[test]
fn kagemusha_wallet_v1_object_digest_domains_are_pinned_and_distinct() {
    assert_eq!(
        KagemushaWalletObjectDigestDomainV1::ALL.len(),
        OBJECT_DOMAINS.len()
    );
    let mut words = BTreeSet::new();
    for (domain, (label, signing)) in KagemushaWalletObjectDigestDomainV1::ALL
        .iter()
        .zip(OBJECT_DOMAINS)
    {
        assert_eq!(domain.as_str(), label);
        assert_eq!(domain.signing_domain().as_str(), signing);
        let mut ascii = [0_u8; 8];
        ascii.copy_from_slice(label.as_bytes());
        assert_eq!(domain.domain(), u64::from_le_bytes(ascii));
        assert!(words.insert(domain.domain()), "{label}");
    }
    // Object-digest domains never collide with a signing domain or another Poseidon domain.
    for signing in KagemushaWalletSigningDomainV1::ALL {
        assert!(words.insert(signing.domain()), "{}", signing.as_str());
    }
    for (name, word) in KAGEMUSHA_WALLET_POSEIDON_DOMAINS_V1 {
        assert!(words.insert(word), "{name}");
    }
    assert_eq!(words.len(), 10 + 16 + 33);
}

#[test]
fn kagemusha_wallet_v1_object_digest_hashes_message_and_numeric_signature_halves() {
    let (signing, _) = key(7);
    let domain = KagemushaWalletSigningDomainV1::Certificate;
    let message = kagemusha_wallet_signing_message_v1(domain, &transcript(domain, 1));
    let (low, _) = low_and_high(&sign(&signing, &message));
    let signature = KagemushaDeviceSignatureV1::from_raw_bytes(&low).expect("low-S");
    let items = kagemusha_wallet_signed_object_items_v1(&message, &signature);
    // `[m, r_lo, r_hi, s_lo, s_hi]`: the numeric 128-bit halves of the big-endian `r` and `s`,
    // each one integer element; no scalar is reduced modulo `p`.
    let half = |offset: usize| {
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&low[offset..offset + 16]);
        kagemusha_wallet_field_from_u128_v1(u128::from_be_bytes(bytes))
    };
    assert_eq!(items, vec![message, half(16), half(0), half(48), half(32)]);
    for object in KagemushaWalletObjectDigestDomainV1::ALL {
        assert_eq!(
            kagemusha_wallet_signed_object_digest_v1(object, &message, &signature),
            crate::kagemusha::kagemusha_wallet_v1::poseidon::kagemusha_wallet_poseidon_v1(
                object.domain(),
                &items
            )
            .expect("canonical items")
        );
    }
    let certificate = kagemusha_wallet_signed_object_digest_v1(
        KagemushaWalletObjectDigestDomainV1::Certificate,
        &message,
        &signature,
    );
    assert!(kagemusha_wallet_is_canonical_field_v1(&certificate));
    assert_ne!(
        certificate,
        kagemusha_wallet_signed_object_digest_v1(
            KagemushaWalletObjectDigestDomainV1::Credential,
            &message,
            &signature
        )
    );
    // Swapping `r` and `s` changes the digest: the halves are positional.
    let mut swapped = [0_u8; 64];
    swapped[..32].copy_from_slice(&low[32..]);
    swapped[32..].copy_from_slice(&low[..32]);
    if let Ok(swapped) = KagemushaDeviceSignatureV1::from_raw_bytes(&swapped) {
        assert_ne!(
            certificate,
            kagemusha_wallet_signed_object_digest_v1(
                KagemushaWalletObjectDigestDomainV1::Certificate,
                &message,
                &swapped
            )
        );
    }
}

#[test]
fn kagemusha_wallet_v1_artifact_manifest_digest_stays_sha256_over_message_then_signature() {
    let (signing, _) = key(8);
    let domain = KagemushaWalletSigningDomainV1::ArtifactManifest;
    let message = kagemusha_wallet_signing_message_v1(domain, &transcript(domain, 2));
    let (low, _) = low_and_high(&sign(&signing, &message));
    let signature = KagemushaDeviceSignatureV1::from_raw_bytes(&low).expect("low-S");
    let mut body = message.to_vec();
    body.extend_from_slice(&low);
    assert_eq!(
        body.len(),
        KAGEMUSHA_WALLET_SIGNED_OBJECT_TRANSCRIPT_BYTES_V1
    );
    assert_eq!(
        kagemusha_wallet_artifact_manifest_digest_v1(&message, &signature),
        kagemusha_wallet_digest_v1(KagemushaWalletDigestRoleV1::ArtifactManifest, &body)
    );
}

#[test]
fn kagemusha_wallet_v1_transcript_builder_writes_fixed_widths() {
    let (signing, public) = key(9);
    let (low, _) = low_and_high(&sign(&signing, &[0x01; 32]));
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
    let domain = KagemushaWalletSigningDomainV1::Credential;
    let message = kagemusha_wallet_signing_message_v1(domain, &transcript(domain, 2));
    let signature = sign(&signing, &message);
    let (low, high) = low_and_high(&signature);
    let der = signature.to_der();
    for output in [
        KagemushaWalletSignerOutputV1::Raw(low),
        KagemushaWalletSignerOutputV1::Raw(high),
        KagemushaWalletSignerOutputV1::Der(der.as_bytes()),
    ] {
        let frozen = kagemusha_wallet_freeze_signature_v1(&public, domain, &message, output)
            .expect("freeze");
        assert_eq!(frozen.as_raw_bytes(), &low);
        kagemusha_wallet_verify_signature_v1(&public, domain, &message, &frozen).expect("verify");
    }
    let high_der = P256Signature::from_slice(&high).expect("high twin parses");
    let frozen = kagemusha_wallet_freeze_signature_v1(
        &public,
        domain,
        &message,
        KagemushaWalletSignerOutputV1::Der(high_der.to_der().as_bytes()),
    )
    .expect("freeze high-S DER");
    assert_eq!(frozen.as_raw_bytes(), &low);
}

#[test]
fn kagemusha_wallet_v1_freeze_rejects_invalid_or_unbound_output() {
    let (signing, public) = key(7);
    let (_, other) = key(8);
    let domain = KagemushaWalletSigningDomainV1::Request;
    let message = kagemusha_wallet_signing_message_v1(domain, &transcript(domain, 3));
    let signature = sign(&signing, &message);
    let (low, _) = low_and_high(&signature);
    let rejected =
        |result: Result<KagemushaDeviceSignatureV1, KagemushaWalletValidationErrorV1>| {
            matches!(
                result,
                Err(KagemushaWalletValidationErrorV1::InvalidSignature {
                    domain: KagemushaWalletSigningDomainV1::Request
                })
            )
        };
    let raw_output = KagemushaWalletSignerOutputV1::Raw(low);
    assert!(rejected(kagemusha_wallet_freeze_signature_v1(
        &other, domain, &message, raw_output
    )));
    let other_message = kagemusha_wallet_signing_message_v1(domain, &transcript(domain, 4));
    assert!(rejected(kagemusha_wallet_freeze_signature_v1(
        &public,
        domain,
        &other_message,
        raw_output
    )));
    let mut der = signature.to_der().as_bytes().to_vec();
    der.push(0);
    assert!(rejected(kagemusha_wallet_freeze_signature_v1(
        &public,
        domain,
        &message,
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
            domain,
            &message,
            KagemushaWalletSignerOutputV1::Raw(invalid)
        )));
    }
}

#[test]
fn kagemusha_wallet_v1_verify_rejects_high_s_wrong_bindings_and_other_messages() {
    let (signing, public) = key(7);
    let (_, other) = key(8);
    let domain = KagemushaWalletSigningDomainV1::Receipt;
    let body = transcript(domain, 5);
    let message = kagemusha_wallet_signing_message_v1(domain, &body);
    let (low, high) = low_and_high(&sign(&signing, &message));
    assert!(KagemushaDeviceSignatureV1::from_raw_bytes(&high).is_err());
    let signature = KagemushaDeviceSignatureV1::from_raw_bytes(&low).expect("low-S");
    assert!(kagemusha_wallet_verify_signature_v1(&public, domain, &message, &signature).is_ok());
    let other_domain = kagemusha_wallet_signing_message_v1(
        KagemushaWalletSigningDomainV1::LedgerControl,
        &transcript(KagemushaWalletSigningDomainV1::LedgerControl, 5),
    );
    for (key, message) in [
        (&other, message),
        (&public, other_domain),
        (&public, [0; 32]),
    ] {
        assert!(matches!(
            kagemusha_wallet_verify_signature_v1(key, domain, &message, &signature),
            Err(KagemushaWalletValidationErrorV1::InvalidSignature { .. })
        ));
    }
    // A signature over anything but the 32-byte message is rejected: the transcript itself,
    // the superseded SHA-256 `H` preimage of the body, and a no-digest (prehash) signature
    // whose ECDSA hash is `m` instead of `SHA-256(m)`.
    let superseded = preimage(KagemushaWalletDigestRoleV1::Output, &body);
    let no_digest: P256Signature = signing.sign_prehash(&message).expect("prehash signature");
    for wrong in [
        signing.sign(&body[..]),
        signing.sign(&superseded[..]),
        no_digest,
    ] {
        let (wrong_low, _) = low_and_high(&wrong);
        let wrong = KagemushaDeviceSignatureV1::from_raw_bytes(&wrong_low).expect("low-S");
        assert!(matches!(
            kagemusha_wallet_verify_signature_v1(&public, domain, &message, &wrong),
            Err(KagemushaWalletValidationErrorV1::InvalidSignature { .. })
        ));
        assert!(
            kagemusha_wallet_freeze_signature_v1(
                &public,
                domain,
                &message,
                KagemushaWalletSignerOutputV1::Raw(wrong_low)
            )
            .is_err()
        );
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
            KagemushaWalletSigningDomainV1::Offer,
            &[0; 32],
            KagemushaWalletSignerOutputV1::Raw(raw(&one, &half_plus_one))
        ),
        Err(KagemushaWalletValidationErrorV1::InvalidSignature {
            domain: KagemushaWalletSigningDomainV1::Offer
        })
    ));
}
