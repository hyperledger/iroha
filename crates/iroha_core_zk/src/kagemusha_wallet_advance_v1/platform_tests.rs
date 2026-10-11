//! Platform interface tests: tri-state answers, boot and clock helpers, and the role-checked
//! signer.

use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};

use iroha_data_model::kagemusha::{
    KagemushaWalletReceiptBodyV1, kagemusha_wallet_verify_signature_v1,
};
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};

use super::*;
use crate::kagemusha_wallet_advance_v1::{
    KagemushaWalletMarkerPublicationV1, KagemushaWalletSelectedCapabilityV1,
    KagemushaWalletSimFsV1, kagemusha_wallet_publish_marker_v1,
    test_support::{
        BOOT_A, SimStoreV1, bootstrap_capsule, prepared_slot, signing_key, wallet_fixture,
    },
};

/// How the fake platform answers `key_sign`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignModeV1 {
    Der,
    Raw,
    RawHighS,
    WrongKey,
    Garbage,
    Unavailable,
}

/// Fake platform holding one software P-256 key.
struct FakePlatformV1 {
    key: SigningKey,
    mode: Mutex<SignModeV1>,
    sign_calls: AtomicUsize,
    signed_messages: Mutex<Vec<(KagemushaWalletSigningDomainV1, [u8; 32])>>,
}

impl FakePlatformV1 {
    fn new(key: SigningKey) -> Self {
        Self {
            key,
            mode: Mutex::new(SignModeV1::Der),
            sign_calls: AtomicUsize::new(0),
            signed_messages: Mutex::new(Vec::new()),
        }
    }

    fn set_mode(&self, mode: SignModeV1) {
        *self.mode.lock().expect("mode") = mode;
    }

    fn calls(&self) -> usize {
        self.sign_calls.load(Ordering::SeqCst)
    }
}

fn high_s(signature: Signature) -> [u8; 64] {
    let low = signature.normalize_s().unwrap_or(signature);
    let (r, s) = low.split_scalars();
    let high = Signature::from_scalars(r.to_bytes(), (-*s.as_ref()).to_bytes()).expect("high S");
    assert!(high.normalize_s().is_some(), "really high S");
    high.to_bytes().as_slice().try_into().expect("raw")
}

impl KagemushaWalletPlatformV1 for FakePlatformV1 {
    fn key_probe(
        &self,
        _slot: &KagemushaWalletSlotIdV1,
    ) -> KagemushaWalletProbeV1<KagemushaDevicePublicKeyV1> {
        KagemushaWalletProbeV1::Present(super::super::test_support::public_key(&self.key))
    }

    fn key_generate(
        &self,
        _slot: &KagemushaWalletSlotIdV1,
        _request: &KagemushaWalletKeyGenerationRequestV1,
    ) -> KagemushaWalletKeyGenerationV1 {
        KagemushaWalletKeyGenerationV1::AlreadyPresent
    }

    fn key_sign(
        &self,
        _slot: &KagemushaWalletSlotIdV1,
        message: KagemushaWalletSigningMessageV1<'_>,
    ) -> Result<KagemushaWalletPlatformSignatureV1, KagemushaWalletUnavailableV1> {
        self.sign_calls.fetch_add(1, Ordering::SeqCst);
        self.signed_messages
            .lock()
            .expect("messages")
            .push((message.domain(), *message.as_bytes()));
        let message = message.as_bytes();
        let signature: Signature = self.key.sign(message);
        Ok(match *self.mode.lock().expect("mode") {
            SignModeV1::Der => {
                KagemushaWalletPlatformSignatureV1::Der(signature.to_der().as_bytes().to_vec())
            }
            SignModeV1::Raw => KagemushaWalletPlatformSignatureV1::Raw(
                signature.to_bytes().as_slice().try_into().expect("raw"),
            ),
            SignModeV1::RawHighS => KagemushaWalletPlatformSignatureV1::Raw(high_s(signature)),
            SignModeV1::WrongKey => {
                let other: Signature = signing_key(0x77).sign(message);
                KagemushaWalletPlatformSignatureV1::Der(other.to_der().as_bytes().to_vec())
            }
            SignModeV1::Garbage => KagemushaWalletPlatformSignatureV1::Der(vec![0x30, 0x01, 0x00]),
            SignModeV1::Unavailable => return Err(KagemushaWalletUnavailableV1::Locked),
        })
    }

    fn key_delete(&self, _slot: &KagemushaWalletSlotIdV1) -> KagemushaWalletRemoveOutcomeV1 {
        KagemushaWalletRemoveOutcomeV1::NotRemoved(KagemushaWalletUnavailableV1::Platform(1))
    }

    fn anchor_policy(&self) -> KagemushaWalletAnchorPolicyV1 {
        KagemushaWalletAnchorPolicyV1::NotRequired
    }

    fn storage_state(&self) -> Result<(), KagemushaWalletUnavailableV1> {
        Ok(())
    }
}

/// Durable Selected-marker capability of the fixture's Bootstrap head, with the store holding
/// its marker.
fn selected_capability(
    seed: u8,
) -> (
    FakePlatformV1,
    KagemushaWalletSimFsV1,
    SimStoreV1,
    KagemushaWalletSelectedCapabilityV1,
) {
    let f = wallet_fixture(seed);
    let (fs, store) = prepared_slot(&f);
    let enrollment = f.enrollment_record(BOOT_A);
    let KagemushaWalletMarkerPublicationV1::Durable(durable) =
        kagemusha_wallet_publish_marker_v1(&store, enrollment.clone()).expect("publish")
    else {
        panic!("enrollment generation taken");
    };
    assert!(
        durable.selected_capability().is_none(),
        "Enrollment grants no signing"
    );
    let capsule = bootstrap_capsule(&f);
    let selected = enrollment
        .select(capsule.head_marker_state().expect("head"), BOOT_A)
        .expect("select");
    let KagemushaWalletMarkerPublicationV1::Durable(durable) =
        kagemusha_wallet_publish_marker_v1(&store, selected).expect("publish")
    else {
        panic!("selected generation taken");
    };
    let capability = durable.selected_capability().expect("capability");
    (FakePlatformV1::new(f.signing), fs, store, capability)
}

#[test]
fn wallet_advance_v1_platform_unavailable_from_io() {
    assert_eq!(
        KagemushaWalletUnavailableV1::from_io(&io::Error::from(io::ErrorKind::WouldBlock)),
        KagemushaWalletUnavailableV1::Busy
    );
    assert_eq!(
        KagemushaWalletUnavailableV1::from_io(&io::Error::from_raw_os_error(5)),
        KagemushaWalletUnavailableV1::Io(5)
    );
    assert_eq!(
        KagemushaWalletUnavailableV1::from_io(&io::Error::other("x")),
        KagemushaWalletUnavailableV1::Io(0)
    );
}

#[test]
fn wallet_advance_v1_platform_probe_conversions() {
    assert_eq!(
        KagemushaWalletProbeV1::Present(3).into_result(),
        Ok(Some(3))
    );
    assert_eq!(KagemushaWalletProbeV1::<u8>::Absent.into_result(), Ok(None));
    assert_eq!(
        KagemushaWalletProbeV1::<u8>::Unavailable(KagemushaWalletUnavailableV1::Locked)
            .into_result(),
        Err(KagemushaWalletProviderErrorV1::Unavailable(
            KagemushaWalletUnavailableV1::Locked
        ))
    );
    assert_eq!(
        KagemushaWalletProbeV1::Present(2).map(|value| value * 2),
        KagemushaWalletProbeV1::Present(4)
    );
    assert_eq!(
        KagemushaWalletProbeV1::<u8>::Absent.map(|value| value * 2),
        KagemushaWalletProbeV1::Absent
    );
    assert_eq!(
        KagemushaWalletProbeV1::<u8>::Unavailable(KagemushaWalletUnavailableV1::Busy)
            .map(|value| value * 2),
        KagemushaWalletProbeV1::Unavailable(KagemushaWalletUnavailableV1::Busy)
    );
}

#[test]
fn wallet_advance_v1_platform_boot_rules() {
    let current = Ok([7; 32]);
    let unavailable = Err(KagemushaWalletUnavailableV1::Platform(0));
    assert_eq!(kagemusha_wallet_boot_stamp_v1(&current), [7; 32]);
    assert_eq!(kagemusha_wallet_boot_stamp_v1(&unavailable), [0; 32]);
    assert!(kagemusha_wallet_written_this_boot_v1(&[7; 32], &current));
    assert!(kagemusha_wallet_written_this_boot_v1(&[0; 32], &current));
    assert!(!kagemusha_wallet_written_this_boot_v1(&[8; 32], &current));
    assert!(kagemusha_wallet_written_this_boot_v1(
        &[8; 32],
        &unavailable
    ));
}

#[test]
fn wallet_advance_v1_platform_boot_id_text() {
    let uuid = "0b9d4f6e-1c2a-4e3b-9f8d-7a6b5c4d3e2f";
    let id = kagemusha_wallet_boot_id_from_text_v1(&format!("{uuid}\n")).expect("boot id");
    assert_eq!(
        kagemusha_wallet_boot_id_from_text_v1(&uuid.to_ascii_uppercase()),
        Ok(id)
    );
    assert_eq!(
        id,
        crate::kagemusha_wallet_advance_v1::kagemusha_wallet_provider_digest_v1(
            "boot-id",
            uuid.as_bytes()
        )
    );
    for invalid in [
        "",
        "0b9d4f6e1c2a4e3b9f8d7a6b5c4d3e2f",
        "0b9d4f6e-1c2a-4e3b-9f8d-7a6b5c4d3e2",
        "0b9d4f6e-1c2a-4e3b-9f8d-7a6b5c4d3e2g",
        "0b9d4f6e-1c2a+4e3b-9f8d-7a6b5c4d3e2f",
    ] {
        assert!(
            kagemusha_wallet_boot_id_from_text_v1(invalid).is_err(),
            "{invalid}"
        );
    }
}

#[test]
fn wallet_advance_v1_platform_native_boot_id_and_clock() {
    let boot = kagemusha_wallet_native_boot_id_v1();
    if cfg!(any(target_os = "linux", target_os = "android")) {
        let boot = boot.expect("linux boot id");
        assert_eq!(
            kagemusha_wallet_native_boot_id_v1(),
            Ok(boot),
            "stable within a boot"
        );
    } else {
        assert_eq!(boot, Err(KagemushaWalletUnavailableV1::Platform(0)));
    }
    let first = kagemusha_wallet_native_monotonic_ms_v1().expect("clock");
    let second = kagemusha_wallet_native_monotonic_ms_v1().expect("clock");
    assert!(second >= first);
    let platform = FakePlatformV1::new(signing_key(0x31));
    assert_eq!(platform.boot_id(), boot);
    assert!(platform.monotonic_ms().expect("default clock") >= first);
    let slot = KagemushaWalletSlotIdV1([1; 32]);
    // The anchor defaults fail closed: never written, never read as absent.
    assert!(matches!(
        platform.anchor_create(&slot, b"a"),
        KagemushaWalletPublishOutcomeV1::NotPublished(_)
    ));
    assert!(matches!(
        platform.anchor_read(&slot),
        KagemushaWalletProbeV1::Unavailable(_)
    ));
    assert!(matches!(
        platform.anchor_update(&slot, b"a"),
        KagemushaWalletPublishOutcomeV1::NotPublished(_)
    ));
    assert_eq!(platform.storage_state(), Ok(()));
    let request = KagemushaWalletKeyGenerationRequestV1 {
        challenge_digest: [3; 32],
        profile: KagemushaWalletKeyProfileV1::SecureElement,
    };
    assert_eq!(
        platform.key_generate(&slot, &request),
        KagemushaWalletKeyGenerationV1::AlreadyPresent
    );
    assert!(matches!(
        platform.key_delete(&slot),
        KagemushaWalletRemoveOutcomeV1::NotRemoved(_)
    ));
    assert!(matches!(
        platform.key_probe(&slot),
        KagemushaWalletProbeV1::Present(_)
    ));
}

#[test]
fn wallet_advance_v1_platform_signature_output_borrows() {
    let der = KagemushaWalletPlatformSignatureV1::Der(vec![1, 2, 3]);
    assert_eq!(
        der.as_signer_output(),
        KagemushaWalletSignerOutputV1::Der(&[1, 2, 3])
    );
    let raw = KagemushaWalletPlatformSignatureV1::Raw([9; 64]);
    assert_eq!(
        raw.as_signer_output(),
        KagemushaWalletSignerOutputV1::Raw([9; 64])
    );
}

#[test]
fn wallet_advance_v1_platform_tags_and_signing_message() {
    for policy in [
        KagemushaWalletAnchorPolicyV1::NotRequired,
        KagemushaWalletAnchorPolicyV1::Keychain,
    ] {
        assert_eq!(
            KagemushaWalletAnchorPolicyV1::from_tag(policy.tag()),
            Some(policy)
        );
    }
    assert_eq!(KagemushaWalletAnchorPolicyV1::Keychain.tag(), 1);
    assert_eq!(KagemushaWalletAnchorPolicyV1::from_tag(2), None);
    for profile in [
        KagemushaWalletKeyProfileV1::SecureElement,
        KagemushaWalletKeyProfileV1::SecureElementOrTee,
    ] {
        assert_eq!(
            KagemushaWalletKeyProfileV1::from_tag(profile.tag()),
            Some(profile)
        );
    }
    assert_eq!(KagemushaWalletKeyProfileV1::from_tag(0), None);
    assert_eq!(KagemushaWalletKeyProfileV1::from_tag(3), None);
    let bytes = [7_u8; 32];
    let message = KagemushaWalletSigningMessageV1 {
        domain: KagemushaWalletSigningDomainV1::Receipt,
        bytes: &bytes,
    };
    assert_eq!(message.as_bytes(), &bytes);
    assert_eq!(message.domain(), KagemushaWalletSigningDomainV1::Receipt);
}

#[test]
fn wallet_advance_v1_platform_receipt_signer_freezes_and_verifies() {
    let (platform, _fs, store, capability) = selected_capability(0x51);
    let body = vec![7; KagemushaWalletSigningDomainV1::Receipt.transcript_bytes()];
    for mode in [SignModeV1::Der, SignModeV1::Raw, SignModeV1::RawHighS] {
        platform.set_mode(mode);
        let signature =
            kagemusha_wallet_sign_receipt_body_v1(&store, &platform, &capability, &body)
                .expect("signed");
        signature.validate().expect("low S");
        kagemusha_wallet_verify_signature_v1(
            capability.payment_key(),
            KagemushaWalletSigningDomainV1::Receipt,
            &kagemusha_wallet_signing_message_v1(KagemushaWalletSigningDomainV1::Receipt, &body),
            &signature,
        )
        .expect("verifies over the exact receipt signing message");
        assert_eq!(
            platform.signed_messages.lock().expect("messages").last(),
            Some(&(
                KagemushaWalletSigningDomainV1::Receipt,
                kagemusha_wallet_signing_message_v1(KagemushaWalletSigningDomainV1::Receipt, &body)
            ))
        );
    }
    // The real G1 receipt body is one admissible transcript.
    let receipt_body = KagemushaWalletReceiptBodyV1 {
        version: 1,
        scheme_id: [1; 32],
        wallet_id: [2; 32],
        provider_contract: [3; 32],
        sequence: 0,
        operation_id: *capability.operation_id(),
        predecessor: iroha_data_model::kagemusha::KagemushaWalletStateCommitmentV1::ZERO,
        successor: iroha_data_model::kagemusha::KagemushaWalletStateCommitmentV1 { value: [4; 32] },
        statement_digest: [6; 32],
        proof_digest: [7; 32],
        capsule_digest: *capability.capsule_digest(),
        payment_digest: [0; 32],
    };
    platform.set_mode(SignModeV1::Der);
    let signature = kagemusha_wallet_sign_receipt_body_v1(
        &store,
        &platform,
        &capability,
        &receipt_body.transcript(),
    )
    .expect("signed");
    signature
        .verify(capability.payment_key(), &receipt_body.signing_message())
        .expect("G1 signing message");
}

#[test]
fn wallet_advance_v1_platform_receipt_signer_rechecks_the_marker_on_disk() {
    // Regression: a capability whose Selected marker is superseded, or a marker that is not
    // on disk, never reaches the key.
    let (platform, fs, store, capability) = selected_capability(0x54);
    let f = wallet_fixture(0x54);
    let released = f
        .enrollment_record(BOOT_A)
        .select(
            bootstrap_capsule(&f).head_marker_state().expect("head"),
            BOOT_A,
        )
        .expect("select")
        .release([0xc5; 32], BOOT_A)
        .expect("release");
    kagemusha_wallet_publish_marker_v1(&store, released).expect("publish released");
    assert_eq!(
        kagemusha_wallet_sign_receipt_body_v1(&store, &platform, &capability, b"second body"),
        Err(KagemushaWalletSignErrorV1::Custody(
            KagemushaWalletProviderErrorV1::Invalid {
                field: "marker.superseded"
            }
        ))
    );
    // A store over an empty filesystem holds no marker at all.
    let (_empty, empty_store) = prepared_slot(&wallet_fixture(0x55));
    assert!(matches!(
        kagemusha_wallet_sign_receipt_body_v1(&empty_store, &platform, &capability, b"body"),
        Err(KagemushaWalletSignErrorV1::Custody(_))
    ));
    // A read error is never a signature either.
    fs.inject(
        fs.steps(),
        crate::kagemusha_wallet_advance_v1::KagemushaWalletSimFaultV1::Error,
    );
    assert!(matches!(
        kagemusha_wallet_sign_receipt_body_v1(&store, &platform, &capability, b"body"),
        Err(KagemushaWalletSignErrorV1::Custody(
            KagemushaWalletProviderErrorV1::Unavailable(_)
        ))
    ));
    assert_eq!(platform.calls(), 0, "the key was never reached");
    assert_eq!(
        KagemushaWalletProviderErrorV1::from(KagemushaWalletSignErrorV1::Custody(
            KagemushaWalletProviderErrorV1::NoSpace
        )),
        KagemushaWalletProviderErrorV1::NoSpace
    );
}

#[test]
fn wallet_advance_v1_platform_receipt_signer_failures_write_nothing() {
    let (platform, _fs, store, capability) = selected_capability(0x52);
    let body = vec![7; KagemushaWalletSigningDomainV1::Receipt.transcript_bytes()];
    for (mode, expected) in [
        (
            SignModeV1::WrongKey,
            KagemushaWalletSignErrorV1::KeyUnusable,
        ),
        (SignModeV1::Garbage, KagemushaWalletSignErrorV1::KeyUnusable),
        (
            SignModeV1::Unavailable,
            KagemushaWalletSignErrorV1::Unavailable(KagemushaWalletUnavailableV1::Locked),
        ),
    ] {
        platform.set_mode(mode);
        assert_eq!(
            kagemusha_wallet_sign_receipt_body_v1(&store, &platform, &capability, &body),
            Err(expected)
        );
    }
    assert_eq!(
        KagemushaWalletProviderErrorV1::from(KagemushaWalletSignErrorV1::KeyUnusable),
        KagemushaWalletProviderErrorV1::Unavailable(KagemushaWalletUnavailableV1::KeyUnusable)
    );
    assert_eq!(
        KagemushaWalletProviderErrorV1::from(KagemushaWalletSignErrorV1::Unavailable(
            KagemushaWalletUnavailableV1::Locked
        )),
        KagemushaWalletProviderErrorV1::Unavailable(KagemushaWalletUnavailableV1::Locked)
    );
    assert_eq!(
        KagemushaWalletProviderErrorV1::from(KagemushaWalletSignErrorV1::RoleNotPermitted),
        KagemushaWalletProviderErrorV1::Invalid {
            field: "signer role"
        }
    );
}

#[test]
fn wallet_advance_v1_platform_role_signer_refuses_receipt_roles() {
    let (platform, _fs, _store, capability) = selected_capability(0x53);
    for role in KAGEMUSHA_WALLET_PAYMENT_KEY_SIGNING_DOMAINS_V1 {
        let body = vec![7; role.transcript_bytes()];
        let signature = kagemusha_wallet_sign_role_v1(
            &platform,
            capability.slot(),
            capability.payment_key(),
            role,
            &body,
        )
        .expect("permitted role");
        assert_eq!(
            platform.signed_messages.lock().expect("messages").last(),
            Some(&(role, kagemusha_wallet_signing_message_v1(role, &body)))
        );
        kagemusha_wallet_verify_signature_v1(
            capability.payment_key(),
            role,
            &kagemusha_wallet_signing_message_v1(role, &body),
            &signature,
        )
        .expect("verifies");
    }
    let calls = platform.calls();
    for role in KagemushaWalletSigningDomainV1::ALL {
        if KAGEMUSHA_WALLET_PAYMENT_KEY_SIGNING_DOMAINS_V1.contains(&role) {
            continue;
        }
        assert_eq!(
            kagemusha_wallet_sign_role_v1(
                &platform,
                capability.slot(),
                capability.payment_key(),
                role,
                b"body",
            ),
            Err(KagemushaWalletSignErrorV1::RoleNotPermitted),
            "{role:?}"
        );
    }
    assert_eq!(platform.calls(), calls, "refused roles never reach the key");
}

#[test]
fn wallet_advance_v1_platform_wrong_transcript_length_never_reaches_the_key() {
    let (platform, _fs, store, capability) = selected_capability(0x56);
    for domain in KAGEMUSHA_WALLET_PAYMENT_KEY_SIGNING_DOMAINS_V1 {
        for length in [domain.transcript_bytes() - 1, domain.transcript_bytes() + 1] {
            assert_eq!(
                kagemusha_wallet_sign_role_v1(
                    &platform,
                    capability.slot(),
                    capability.payment_key(),
                    domain,
                    &vec![7; length]
                ),
                Err(KagemushaWalletSignErrorV1::InvalidTranscript),
            );
        }
    }
    assert_eq!(
        kagemusha_wallet_sign_receipt_body_v1(&store, &platform, &capability, b"short"),
        Err(KagemushaWalletSignErrorV1::InvalidTranscript),
    );
    assert_eq!(platform.calls(), 0);
    assert_eq!(
        KagemushaWalletProviderErrorV1::from(KagemushaWalletSignErrorV1::InvalidTranscript),
        KagemushaWalletProviderErrorV1::Invalid {
            field: "signer transcript"
        }
    );
}
