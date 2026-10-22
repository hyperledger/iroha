//! Shared-root enrollment across independent schemes using real owner transitions and
//! explicit simulated hardware. No device attestation or monetary-proof claim is made.

use super::*;
use crate::kagemusha_wallet_advance_v1::{
    enrollment_phase::{test_decode_phase_record, test_phase_record},
    layout::kagemusha_wallet_slot_dir_v1,
    prekey_custody::PreKeySlotSelectionV1,
};
use std::collections::BTreeMap;

const OLD_REQUEST: [u8; 32] = [11; 32];
const NEW_REQUEST: [u8; 32] = [12; 32];

fn next_scheme(apple: bool) -> Fixture {
    let mut f = if apple {
        apple_collection_fixture()
    } else {
        fixture()
    };
    f.config.scheme.network_id = *Hash::new(b"independent successor enrollment network").as_ref();
    let scheme_id = f.config.scheme.scheme_id();
    f.config.installation.scheme_id = scheme_id;
    f.config.app.scheme_id = scheme_id;
    f.config.policy.scheme_id = scheme_id;
    f.config.policy.app_policy = f.config.app.policy_digest().unwrap();
    f.config.enrollment_certificate = enrollment_certificate(&f.config.scheme);
    f.challenge.scheme_id = scheme_id;
    f.challenge.app_policy = f.config.app.policy_digest().unwrap();
    f.challenge.enrollment_policy = f.config.policy.policy_digest().unwrap();
    f.challenge.issuer_nonce = [48; 32];
    f
}

fn begin_request(f: &Fixture, current: &mut Owner, id: &[u8; 32]) -> [u8; 32] {
    let dispatch = PreKeyDispatchV1::decode(
        &current
            .begin(
                id,
                &norito::encode_canonical(&f.account).unwrap(),
                &norito::encode_canonical(&f.asset).unwrap(),
            )
            .unwrap(),
    )
    .unwrap();
    current
        .accept_permit(&permit(f, &dispatch).encode_canonical().unwrap())
        .unwrap()
}

fn prekey_name(id: &[u8; 32], role: &str) -> String {
    format!("prekey-{}-{role}.norito", hex::encode(id))
}

fn file_snapshot(d: &DeviceV1) -> BTreeMap<(KagemushaWalletCustodyDirV1, String), Vec<u8>> {
    fn visit(
        d: &DeviceV1,
        dir: KagemushaWalletCustodyDirV1,
        files: &mut BTreeMap<(KagemushaWalletCustodyDirV1, String), Vec<u8>>,
    ) {
        for name in d.fs.visible_names(&dir) {
            if let Some(bytes) = d.fs.visible_file(&dir, &name) {
                files.insert((dir.clone(), name), bytes);
            } else {
                let child = dir.child(&KagemushaWalletEntryNameV1::new(&name).unwrap());
                assert!(
                    d.fs.visible_dir(&child),
                    "fixture contains only ordinary files/directories"
                );
                visit(d, child, files);
            }
        }
    }
    let mut files = BTreeMap::new();
    visit(d, KagemushaWalletCustodyDirV1::root(), &mut files);
    files
}

fn assert_files_preserved(
    d: &DeviceV1,
    before: &BTreeMap<(KagemushaWalletCustodyDirV1, String), Vec<u8>>,
) {
    for ((dir, name), bytes) in before {
        assert_eq!(
            d.fs.visible_file(dir, name).as_ref(),
            Some(bytes),
            "retained original changed: {}/{}",
            dir.label(),
            name
        );
    }
}

fn old_enrollment(
    apple: bool,
    completed: bool,
    seed: u8,
) -> (Fixture, DeviceV1, KagemushaWalletSlotIdV1) {
    let f = if apple {
        apple_collection_fixture()
    } else {
        fixture()
    };
    let d = DeviceV1::new(
        if apple {
            KagemushaWalletAnchorPolicyV1::Keychain
        } else {
            KagemushaWalletAnchorPolicyV1::NotRequired
        },
        seed,
    );
    let mut current = enrolled(&f, &d);
    let state = fixture_phase(current.test_provider()).unwrap();
    assert!(matches!(
        state.phase,
        KagemushaWalletEnrollmentPhaseV1::MarkerCommitted { .. }
    ));
    let slot = KagemushaWalletSlotIdV1(state.binding.slot);
    if completed {
        // The existing component issuer signs a complete Android E6. It authenticates the
        // real owner request and persists its credential, without pretending to attest hardware.
        assert!(!apple);
        let request = request(&f, &mut current);
        let issued = issuer_result(&f, &RequestV1::decode(&request).unwrap())
            .encode()
            .unwrap();
        assert_eq!(current.accept_credential(&issued).unwrap(), issued);
        assert_eq!(current.retained_result().unwrap(), Some(issued));
    }
    drop(current);
    (f, d, slot)
}

#[test]
fn enrollment_owner_new_scheme_preserves_old_apple_custody_and_resumes_exact_attempt() {
    let (old, d, old_slot) = old_enrollment(true, false, 211);
    let next = next_scheme(true);
    assert_ne!(
        old.config.scheme.scheme_id(),
        next.config.scheme.scheme_id()
    );
    let before = file_snapshot(&d);
    let old_key = d.platform.key_of(&old_slot).unwrap();
    let old_anchor = d.platform.with(|s| s.anchors[&old_slot].clone());

    let mut current = owner(&next, &d);
    let message = begin_request(&next, &mut current, &NEW_REQUEST);
    let EnrollmentProgressV1::Evidence { slot, .. } = current
        .authorize(&sign(&next, &message))
        .expect("fresh scheme enrollment alongside intact old Apple custody")
    else {
        panic!("new enrollment reaches its own evidence step")
    };
    let new_slot = KagemushaWalletSlotIdV1(slot);
    assert_ne!(new_slot, old_slot);
    let new_key = d.platform.key_of(&new_slot).unwrap();
    let new_phase = current
        .test_provider()
        .enrollment_phase(&NEW_REQUEST)
        .unwrap()
        .unwrap();
    assert_eq!(new_phase.binding.slot, slot);
    assert_files_preserved(&d, &before);
    drop(current);
    d.fs.restart();

    let mut resumed = owner(&next, &d);
    let message = begin_request(&next, &mut resumed, &NEW_REQUEST);
    assert!(matches!(resumed.authorize(&sign(&next, &message)).unwrap(),
        EnrollmentProgressV1::Evidence { slot: same, .. } if same == slot));
    assert_eq!(
        resumed
            .test_provider()
            .enrollment_phase(&NEW_REQUEST)
            .unwrap(),
        Some(new_phase)
    );
    assert_eq!(d.platform.key_of(&new_slot), Some(new_key));
    assert_eq!(d.platform.key_of(&old_slot), Some(old_key));
    assert_files_preserved(&d, &before);
    d.platform.with(|s| {
        assert_eq!(s.anchors[&old_slot], old_anchor);
        assert_eq!(
            s.generate_calls, 2,
            "one old and one new key; retry generates nothing"
        );
        assert_eq!(s.delete_calls, 0);
        assert!(s.violations.is_empty());
    });
}

#[test]
fn enrollment_owner_new_scheme_accepts_fresh_setup_beside_completed_old_e6() {
    let (old, d, old_slot) = old_enrollment(false, true, 213);
    // Actual Android custody policy: no Apple Keychain enumeration or anchor behavior.
    let mut reopened = owner(&old, &d);
    dispatch(&old, &mut reopened);
    let old_result = reopened.retained_result().unwrap().unwrap();
    let old_originals = reopened.open_originals().unwrap();
    drop(reopened);
    let next = next_scheme(false);
    let before = file_snapshot(&d);
    let old_key = d.platform.key_of(&old_slot).unwrap();
    let mut current = owner(&next, &d);
    let message = begin_request(&next, &mut current, &NEW_REQUEST);
    let EnrollmentProgressV1::Evidence { slot, .. } =
        current.authorize(&sign(&next, &message)).unwrap()
    else {
        panic!("new Android enrollment reaches evidence")
    };
    assert_ne!(slot, old_slot.0);
    let new_key = d.platform.key_of(&KagemushaWalletSlotIdV1(slot)).unwrap();
    drop(current);
    d.fs.restart();
    let mut resumed = owner(&next, &d);
    let message = begin_request(&next, &mut resumed, &NEW_REQUEST);
    assert!(matches!(resumed.authorize(&sign(&next, &message)).unwrap(),
        EnrollmentProgressV1::Evidence { slot: same, .. } if same == slot));
    drop(resumed);
    let mut old_reopened = owner(&old, &d);
    dispatch(&old, &mut old_reopened);
    assert_eq!(old_reopened.retained_result().unwrap(), Some(old_result));
    assert_eq!(old_reopened.open_originals().unwrap(), old_originals);
    assert_files_preserved(&d, &before);
    assert_eq!(d.platform.key_of(&old_slot), Some(old_key));
    assert_eq!(
        d.platform.key_of(&KagemushaWalletSlotIdV1(slot)),
        Some(new_key)
    );
    d.platform.with(|s| {
        assert!(s.anchors.is_empty());
        assert_eq!(s.generate_calls, 2);
        assert_eq!(s.delete_calls, 0);
        assert!(s.violations.is_empty());
    });
}

#[test]
fn enrollment_owner_foreign_inventory_never_admits_old_slot_as_current() {
    let (_, d, old_slot) = old_enrollment(true, false, 215);
    let next = next_scheme(true);
    let before = file_snapshot(&d);
    let mut current = owner(&next, &d);
    assert!(
        current
            .test_provider()
            .enrollment_phase(&OLD_REQUEST)
            .is_err()
    );
    assert!(current.test_provider().read_intent(&old_slot).is_err());
    assert!(current.test_provider().status(&old_slot).is_err());
    assert_files_preserved(&d, &before);
    d.platform.with(|s| {
        assert_eq!(s.generate_calls, 1);
        assert_eq!(s.delete_calls, 0);
    });
}

#[test]
fn enrollment_owner_corrupt_foreign_custody_never_becomes_an_ignored_inventory_entry() {
    for case in [
        "missing_phase",
        "malformed_phase",
        "missing_intent",
        "changed_intent",
        "changed_slot",
        "rebound_invalid_issuer_signature",
    ] {
        let (_, d, old_slot) = old_enrollment(true, false, 217);
        let root = KagemushaWalletCustodyDirV1::root();
        let phase_name = prekey_name(&OLD_REQUEST, "phase");
        let slot_name = prekey_name(&OLD_REQUEST, "slot");
        let accepted_name = prekey_name(&OLD_REQUEST, "accepted");
        let dir = kagemusha_wallet_slot_dir_v1(&old_slot);
        match case {
            "missing_phase" => {
                d.fs.unlink(&root, &phase_name).unwrap();
            }
            "malformed_phase" => {
                d.fs.place_unsynced(&root, &phase_name, b"corrupt phase");
            }
            "missing_intent" => {
                d.fs.unlink(&dir, "intent.norito").unwrap();
            }
            "changed_intent" => {
                d.fs.place_unsynced(&dir, "intent.norito", b"corrupt intent");
            }
            "changed_slot" => {
                let bytes = d.fs.visible_file(&root, &slot_name).unwrap();
                let mut selected: PreKeySlotSelectionV1 = norito::decode_canonical(&bytes).unwrap();
                selected.slot[0] ^= 1;
                d.fs.place_unsynced(
                    &root,
                    &slot_name,
                    &norito::encode_canonical(&selected).unwrap(),
                );
            }
            "rebound_invalid_issuer_signature" => {
                let mut accepted = d.fs.visible_file(&root, &accepted_name).unwrap();
                *accepted.last_mut().unwrap() ^= 1;
                let digest =
                    crate::kagemusha_wallet_advance_v1::kagemusha_wallet_prekey_permit_digest_v1(
                        &accepted,
                    );
                let mut phase =
                    test_decode_phase_record(&d.fs.visible_file(&root, &phase_name).unwrap());
                phase.binding.permit_digest = digest;
                let mut selected: PreKeySlotSelectionV1 =
                    norito::decode_canonical(&d.fs.visible_file(&root, &slot_name).unwrap())
                        .unwrap();
                selected.permit_digest = digest;
                d.fs.place_unsynced(&root, &accepted_name, &accepted);
                d.fs.place_unsynced(&root, &phase_name, &test_phase_record(&phase));
                d.fs.place_unsynced(
                    &root,
                    &slot_name,
                    &norito::encode_canonical(&selected).unwrap(),
                );
            }
            _ => unreachable!(),
        }
        let before = file_snapshot(&d);
        let old_key = d.platform.key_of(&old_slot).unwrap();
        let old_anchor = d.platform.with(|s| s.anchors[&old_slot].clone());
        let next = next_scheme(true);
        let mut current = owner(&next, &d);
        let message = begin_request(&next, &mut current, &NEW_REQUEST);
        assert!(current.authorize(&sign(&next, &message)).is_err(), "{case}");
        assert_files_preserved(&d, &before);
        assert_eq!(d.platform.key_of(&old_slot), Some(old_key));
        d.platform.with(|s| {
            assert_eq!(s.anchors[&old_slot], old_anchor, "{case}");
            assert_eq!(s.generate_calls, 1, "no new key for {case}");
            assert_eq!(s.delete_calls, 0, "{case}");
        });
    }
}

#[test]
fn enrollment_owner_current_phase_cannot_be_relabelled_as_foreign_inventory() {
    let (_, d, old_slot) = old_enrollment(true, false, 219);
    let root = KagemushaWalletCustodyDirV1::root();
    let name = prekey_name(&OLD_REQUEST, "phase");
    let mut phase = test_decode_phase_record(&d.fs.visible_file(&root, &name).unwrap());
    // Keep the current-scheme intent, marker, key, Client and signed Accepted original.
    // A scheme-only change to Phase must not reclassify conflicting current custody.
    phase.binding.challenge.scheme_id = next_scheme(true).config.scheme.scheme_id();
    d.fs.place_unsynced(&root, &name, &test_phase_record(&phase));
    let before = file_snapshot(&d);
    let old_key = d.platform.key_of(&old_slot).unwrap();
    let mut next = apple_collection_fixture();
    next.challenge.issuer_nonce = [49; 32];
    let mut current = owner(&next, &d);
    let message = begin_request(&next, &mut current, &NEW_REQUEST);
    assert!(
        current.authorize(&sign(&next, &message)).is_err(),
        "a foreign-labelled Phase does not override current intent custody"
    );
    assert_files_preserved(&d, &before);
    assert_eq!(d.platform.key_of(&old_slot), Some(old_key));
    d.platform.with(|s| {
        assert_eq!(s.generate_calls, 1);
        assert_eq!(s.delete_calls, 0);
    });
}

#[test]
fn enrollment_owner_current_preintent_preserves_generation_policy_beside_foreign_wallet() {
    for policy in [
        KagemushaWalletKeyGenerationPolicyV1::DefinitiveAbsence,
        KagemushaWalletKeyGenerationPolicyV1::FreshEnrollmentOnly,
    ] {
        let apple = policy == KagemushaWalletKeyGenerationPolicyV1::DefinitiveAbsence;
        let (_, d, old_slot) = old_enrollment(apple, !apple, 221);
        let before = file_snapshot(&d);
        let old_key = d.platform.key_of(&old_slot).unwrap();
        let next = next_scheme(apple);
        d.platform.with(|s| s.generation_policy = policy);
        let mut current = owner(&next, &d);
        let message = begin_request(&next, &mut current, &NEW_REQUEST);
        // The existing pre-key fixture's clock cut: Slot and PreIntent are durable,
        // while E2 and every new key effect have not started.
        d.platform.with(|s| {
            s.monotonic_script = [Ok(1000), Err(KagemushaWalletUnavailableV1::Busy)].into()
        });
        assert!(current.authorize(&sign(&next, &message)).is_err());
        let phase = current
            .test_provider()
            .enrollment_phase(&NEW_REQUEST)
            .unwrap()
            .unwrap();
        assert!(matches!(
            phase.phase,
            KagemushaWalletEnrollmentPhaseV1::PreIntent
        ));
        assert_eq!(phase.binding.generation_policy, policy.tag());
        d.platform.with(|s| {
            s.monotonic_script.clear();
            assert_eq!(s.generate_calls, 1);
        });
        drop(current);
        d.fs.restart();
        let mut resumed = owner(&next, &d);
        let message = begin_request(&next, &mut resumed, &NEW_REQUEST);
        let progress = resumed.authorize(&sign(&next, &message)).unwrap();
        if policy == KagemushaWalletKeyGenerationPolicyV1::DefinitiveAbsence {
            assert!(
                matches!(progress, EnrollmentProgressV1::Evidence { slot, .. } if slot == phase.binding.slot)
            );
        } else {
            // Android FreshEnrollmentOnly never turns a loaded attempt into a generation grant.
            assert!(matches!(progress, EnrollmentProgressV1::Pending));
            assert_eq!(
                resumed
                    .test_provider()
                    .enrollment_phase(&NEW_REQUEST)
                    .unwrap(),
                Some(phase)
            );
            d.platform.with(|s| assert_eq!(s.generate_calls, 1));
            assert_eq!(
                resumed.abandon().unwrap(),
                EnrollmentAbandonmentV1::LocalAbandoned
            );
            assert_eq!(resumed.abandonment_ledger_instruction().unwrap(), None);
            assert!(matches!(
                resumed.progress().unwrap(),
                EnrollmentProgressV1::Abandoned
            ));
            drop(resumed);
            let mut fresh = owner(&next, &d);
            let message = begin_request(&next, &mut fresh, &[13; 32]);
            assert!(matches!(fresh.authorize(&sign(&next, &message)).unwrap(),
                EnrollmentProgressV1::Evidence { slot, .. } if slot != phase.binding.slot && slot != old_slot.0));
        }
        assert_files_preserved(&d, &before);
        assert_eq!(d.platform.key_of(&old_slot), Some(old_key));
        d.platform.with(|s| {
            assert_eq!(s.generate_calls, 2);
            assert_eq!(s.delete_calls, 0);
            assert!(s.violations.is_empty());
        });
    }
}

#[test]
fn enrollment_owner_foreign_profile_must_match_its_signed_platform_policy() {
    use crate::kagemusha_wallet_advance_v1::{
        encode_envelope_v1, enrollment::KAGEMUSHA_WALLET_INTENT_MAX_BYTES_V1,
        enrollment_phase::kagemusha_wallet_intent_digest_v1,
    };
    let (_, d, old_slot) = old_enrollment(true, false, 223);
    let root = KagemushaWalletCustodyDirV1::root();
    let phase_name = prekey_name(&OLD_REQUEST, "phase");
    let mut phase = test_decode_phase_record(&d.fs.visible_file(&root, &phase_name).unwrap());
    // Keep the issuer-signed Apple dispatch/permit intact; coherently rewrite only the
    // unsigned phase/intent profile and their digest. Self-consistency cannot change policy.
    phase.binding.profile = KagemushaWalletKeyProfileV1::SecureElementOrTee.tag();
    let intent = phase.binding.intent();
    let KagemushaWalletEnrollmentPhaseV1::MarkerCommitted { intent_digest, .. } = &mut phase.phase
    else {
        panic!("old fixture reached E4")
    };
    *intent_digest = kagemusha_wallet_intent_digest_v1(&intent).unwrap();
    d.fs.place_unsynced(&root, &phase_name, &test_phase_record(&phase));
    d.fs.place_unsynced(
        &kagemusha_wallet_slot_dir_v1(&old_slot),
        "intent.norito",
        &encode_envelope_v1(&intent, KAGEMUSHA_WALLET_INTENT_MAX_BYTES_V1).unwrap(),
    );
    let before = file_snapshot(&d);
    let old_key = d.platform.key_of(&old_slot).unwrap();
    let next = next_scheme(true);
    let mut current = owner(&next, &d);
    let message = begin_request(&next, &mut current, &NEW_REQUEST);
    assert!(
        current.authorize(&sign(&next, &message)).is_err(),
        "a foreign phase cannot rewrite the signed hardware policy"
    );
    assert_files_preserved(&d, &before);
    assert_eq!(d.platform.key_of(&old_slot), Some(old_key));
    d.platform.with(|s| {
        assert_eq!(s.generate_calls, 1);
        assert_eq!(s.delete_calls, 0);
    });
}

#[test]
fn enrollment_owner_unreadable_foreign_phase_is_not_absent_inventory() {
    use crate::kagemusha_wallet_advance_v1::store::{
        KagemushaWalletSimFaultV1, KagemushaWalletSimStepV1,
    };
    let (_, d, old_slot) = old_enrollment(true, false, 225);
    let next = next_scheme(true);
    let current = owner(&next, &d);
    let provider = current.into_provider();
    let absent_slot = KagemushaWalletSlotIdV1([226; 32]);
    // A missing queried slot still scans all Phase originals. Locate its first read,
    // which is the retained foreign Phase, without relying on a hard-coded step count.
    let start = d.fs.steps();
    let _ = provider.enrollment_phase_for_slot(&absent_slot);
    let read =
        d.fs.trace_since(start)
            .iter()
            .position(|s| *s == KagemushaWalletSimStepV1::Read)
            .unwrap();
    let before = file_snapshot(&d);
    let old_key = d.platform.key_of(&old_slot).unwrap();
    let start = d.fs.steps();
    d.fs.inject(
        start + u64::try_from(read).unwrap(),
        KagemushaWalletSimFaultV1::Error,
    );
    assert!(matches!(
        provider.enrollment_phase_for_slot(&absent_slot),
        Err(KagemushaWalletProviderErrorV1::Unavailable(_))
    ));
    d.fs.clear_faults();
    assert_files_preserved(&d, &before);
    assert_eq!(d.platform.key_of(&old_slot), Some(old_key));
    d.platform.with(|s| {
        assert_eq!(s.generate_calls, 1);
        assert_eq!(s.delete_calls, 0);
    });
}

#[test]
fn enrollment_owner_completed_foreign_wallet_does_not_block_current_intake() {
    use crate::kagemusha_wallet_intake_v1::{Error as IntakeError, select_enrolled_source};
    let (_, d, old_slot) = old_enrollment(false, true, 227);
    let before = file_snapshot(&d);
    let old_key = d.platform.key_of(&old_slot).unwrap();
    let next = next_scheme(false);
    let mut current = owner(&next, &d);
    let message = begin_request(&next, &mut current, &NEW_REQUEST);
    let EnrollmentProgressV1::Evidence { slot, .. } =
        current.authorize(&sign(&next, &message)).unwrap()
    else {
        panic!("new enrollment reaches E4")
    };
    let issued = issuer_result(
        &next,
        &RequestV1::decode(&request(&next, &mut current)).unwrap(),
    );
    current
        .accept_credential(&issued.encode().unwrap())
        .unwrap();
    let credential = KagemushaWalletCredentialV1::decode_canonical(
        &issued.credential,
        &next.config.scheme.scheme_id(),
    )
    .unwrap();
    credential
        .verify(&next.config.scheme, &next.config.enrollment_certificate)
        .unwrap();
    let mut provider = current.into_provider();
    // This is the actual source-selection path used by Native wallet-open after its
    // credential authentication. No installed producer or monetary operation is simulated.
    let opened =
        select_enrolled_source(&mut provider, &credential, &issued.credential, None).unwrap();
    assert_eq!(opened.0, KagemushaWalletSlotIdV1(slot));
    assert_eq!(
        select_enrolled_source(&mut provider, &credential, &issued.credential, Some(opened))
            .unwrap(),
        opened
    );
    assert!(matches!(
        select_enrolled_source(
            &mut provider,
            &credential,
            &issued.credential,
            Some((old_slot, [1; 32]))
        ),
        Err(IntakeError::SourceChanged)
    ));
    drop(provider);
    d.fs.restart();
    let mut reopened = owner(&next, &d);
    let dispatch = PreKeyDispatchV1::decode(
        &reopened
            .begin(
                &NEW_REQUEST,
                &norito::encode_canonical(&next.account).unwrap(),
                &norito::encode_canonical(&next.asset).unwrap(),
            )
            .unwrap(),
    )
    .unwrap();
    assert!(dispatch.previous_permit.is_some());
    assert_eq!(
        reopened.retained_result().unwrap(),
        Some(issued.encode().unwrap())
    );
    let mut provider = reopened.into_provider();
    assert_eq!(
        select_enrolled_source(&mut provider, &credential, &issued.credential, Some(opened))
            .unwrap(),
        opened
    );
    assert_files_preserved(&d, &before);
    assert_eq!(d.platform.key_of(&old_slot), Some(old_key));
    // A valid current source cannot make a malformed foreign original disappear.
    let root = KagemushaWalletCustodyDirV1::root();
    let name = prekey_name(&OLD_REQUEST, "phase");
    let original = d.fs.visible_file(&root, &name).unwrap();
    d.fs.place_unsynced(&root, &name, b"changed foreign phase");
    assert!(
        select_enrolled_source(&mut provider, &credential, &issued.credential, Some(opened))
            .is_err()
    );
    d.fs.place_unsynced(&root, &name, &original);
    assert_files_preserved(&d, &before);
    d.platform.with(|s| {
        assert_eq!(s.generate_calls, 2);
        assert_eq!(s.delete_calls, 0);
        assert!(s.anchors.is_empty());
        assert!(s.violations.is_empty());
    });
}
