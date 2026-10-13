//! E1 expiry recovery controls over the provider simulator, without device admission claims.

use super::*;
use p256::ecdsa::{Signature as P256Signature, signature::Signer as _};

fn resumed(f: &Fixture, d: &DeviceV1) -> (Owner, PreKeyDispatchV1) {
    let mut current = owner(f, d);
    let first = dispatch(f, &mut current);
    current
        .accept_permit(&permit(f, &first).encode_canonical().unwrap())
        .unwrap();
    drop(current);
    d.fs.restart();
    let mut current = owner(f, d);
    let dispatch = dispatch(f, &mut current);
    (current, dispatch)
}

fn body(f: &Fixture, dispatch: &PreKeyDispatchV1) -> KagemushaEnrollmentExpiryProofBodyV1 {
    let accepted = dispatch.previous_permit.as_ref().unwrap();
    let permit = KagemushaEnrollmentPermitV1::decode_canonical(
        accepted,
        &f.config.scheme,
        &f.config.enrollment_certificate,
    )
    .unwrap();
    KagemushaEnrollmentExpiryProofBodyV1::new(
        dispatch.request_id,
        Sha256::digest(dispatch.encode().unwrap()).into(),
        Sha256::digest(accepted).into(),
        permit.body.attempt_id,
        permit.body.challenge.challenge_digest(),
        permit.body.expires_at_ms,
        permit.body.expires_at_ms + 1,
    )
}

fn signed(body: KagemushaEnrollmentExpiryProofBodyV1, key: u8) -> Vec<u8> {
    let signature: P256Signature = signing_key(key).sign(&body.signing_message().unwrap());
    // Deliberately allow malformed DATA bodies here to exercise Native's own validation.
    norito::encode_canonical(&KagemushaEnrollmentExpiryProofV1 {
        body,
        signature: KagemushaDeviceSignatureV1::from_der_normalizing_low_s(
            signature.to_der().as_bytes(),
        )
        .unwrap(),
    })
    .unwrap()
}

fn expired_name(d: &DeviceV1) -> Option<String> {
    d.fs.visible_names(&KagemushaWalletCustodyDirV1::root())
        .into_iter()
        .find(|name| name.ends_with("-expired.norito"))
}

#[test]
fn expired_prekey_restart_recovers_native_completion_and_blocks_all_key_effects() {
    let f = fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 190);
    let (mut current, first) = resumed(&f, &d);
    let proof = signed(body(&f, &first), 79);
    assert_eq!(
        current.abandon_expired(&proof).unwrap(),
        EnrollmentAbandonmentV1::LocalAbandoned
    );
    assert!(expired_name(&d).is_some());
    for _ in 0..2 {
        assert_eq!(
            current.abandon_expired(&proof).unwrap(),
            EnrollmentAbandonmentV1::LocalAbandoned
        );
        assert_eq!(current.abandonment_ledger_instruction().unwrap(), None);
    }
    // Native succeeded but the app's completion DATA was never written.
    drop(current);
    d.fs.restart();
    let mut current = owner(&f, &d);
    let new_dispatch = dispatch(&f, &mut current);
    assert_ne!(
        new_dispatch.native_dispatch_nonce,
        first.native_dispatch_nonce
    );
    assert!(current.retained_request().unwrap().is_none());
    assert!(current.retained_result().unwrap().is_none());
    let new_proof = signed(body(&f, &new_dispatch), 79);
    assert_ne!(new_proof, proof);
    assert_eq!(
        current.abandon_expired(&new_proof).unwrap(),
        EnrollmentAbandonmentV1::LocalAbandoned
    );
    assert_eq!(
        current.abandon().unwrap(),
        EnrollmentAbandonmentV1::LocalAbandoned
    );
    let resumed_permit = permit(&f, &new_dispatch).encode_canonical().unwrap();
    assert!(current.accept_permit(&resumed_permit).is_err());
    assert!(current.authorize(&[1; 64]).is_err());
    let provider = current.into_provider();
    assert_eq!(
        provider
            .prekey_read(&[11; 32], PreKeyRecordV1::Expired)
            .unwrap(),
        Some(proof)
    );
    drop(provider);
    d.platform.with(|s| assert_eq!(s.generate_calls, 0));
    // Another request can begin; no prior Client, Accepted or Expired record is removed.
    let mut current = owner(&f, &d);
    current
        .begin(
            &[12; 32],
            &norito::encode_canonical(&f.account).unwrap(),
            &norito::encode_canonical(&f.asset).unwrap(),
        )
        .unwrap();
    assert_eq!(
        current.abandon().unwrap(),
        EnrollmentAbandonmentV1::LocalAbandoned
    );
}

#[test]
fn expired_prekey_first_publication_requires_every_binding_and_valid_signature() {
    let f = fixture();
    for change in 0..9 {
        let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 191);
        let (mut current, dispatch) = resumed(&f, &d);
        let mut changed = body(&f, &dispatch);
        match change {
            0 => changed.request_id[0] ^= 1,
            1 => changed.dispatch_sha256[0] ^= 1,
            2 => changed.permit_sha256[0] ^= 1,
            3 => changed.attempt_id[0] ^= 1,
            4 => changed.challenge_digest[0] ^= 1,
            5 => {
                changed.expires_at_ms += 1;
                changed.observed_at_ms += 1;
            }
            6 => changed.observed_at_ms = changed.expires_at_ms - 1,
            7 => changed.refusal_code = 11,
            _ => {}
        }
        assert!(
            current
                .abandon_expired(&signed(changed, if change == 8 { 80 } else { 79 }))
                .is_err(),
            "mutation {change}"
        );
        assert!(expired_name(&d).is_none());
        assert!(current.abandon().is_err());
        d.platform.with(|s| assert_eq!(s.generate_calls, 0));
    }
}

#[test]
fn expired_prekey_refuses_selected_slot_phase_and_lost_associations() {
    let f = fixture();
    for erased in 0..3 {
        let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 192);
        drop(enrolled(&f, &d));
        let root = KagemushaWalletCustodyDirV1::root();
        let names = d.fs.visible_names(&root);
        if erased >= 1 {
            let slot = names
                .iter()
                .find(|name| name.ends_with("-slot.norito"))
                .unwrap();
            d.fs.unlink(&root, slot).unwrap();
        }
        if erased >= 2 {
            let phase = names
                .iter()
                .find(|name| name.ends_with("-phase.norito"))
                .unwrap();
            d.fs.unlink(&root, phase).unwrap();
        }
        let mut current = owner(&f, &d);
        let resumed = dispatch(&f, &mut current);
        assert!(
            current
                .abandon_expired(&signed(body(&f, &resumed), 79))
                .is_err(),
            "erased {erased}"
        );
        assert!(expired_name(&d).is_none());
        d.platform.with(|s| assert_eq!(s.generate_calls, 1));
    }
}

#[test]
fn expired_prekey_corrupt_terminal_marker_or_lost_originals_never_recover_as_absence() {
    let f = fixture();
    for damaged in ["expired", "client", "accepted"] {
        let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 193);
        let (mut current, resumed) = resumed(&f, &d);
        current
            .abandon_expired(&signed(body(&f, &resumed), 79))
            .unwrap();
        drop(current);
        let root = KagemushaWalletCustodyDirV1::root();
        let name =
            d.fs.visible_names(&root)
                .into_iter()
                .find(|name| name.ends_with(&format!("-{damaged}.norito")))
                .unwrap();
        if damaged == "expired" {
            d.fs.place_unsynced(&root, &name, b"corrupt expiry proof");
        } else {
            d.fs.unlink(&root, &name).unwrap();
        }
        let mut current = owner(&f, &d);
        assert!(
            current
                .begin(
                    &[11; 32],
                    &norito::encode_canonical(&f.account).unwrap(),
                    &norito::encode_canonical(&f.asset).unwrap()
                )
                .is_err()
        );
        assert!(current.abandon().is_err());
        assert!(current.authorize(&[1; 64]).is_err());
        d.platform.with(|s| assert_eq!(s.generate_calls, 0));
    }
}

#[test]
fn expired_prekey_uncertain_marker_requires_durable_adoption_before_success() {
    let f = fixture();
    let baseline = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 194);
    let (mut current, resumed_dispatch) = resumed(&f, &baseline);
    let proof = signed(body(&f, &resumed_dispatch), 79);
    let start = baseline.fs.steps();
    current.abandon_expired(&proof).unwrap();
    let trace = baseline.fs.trace_since(start);
    let rename = trace
        .iter()
        .rposition(|step| *step == KagemushaWalletSimStepV1::RenameNoReplace)
        .unwrap();
    let sync = rename
        + trace[rename..]
            .iter()
            .position(|step| *step == KagemushaWalletSimStepV1::SyncDir)
            .unwrap();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 194);
    let (mut current, resumed_dispatch) = resumed(&f, &d);
    let proof = signed(body(&f, &resumed_dispatch), 79);
    d.fs.inject(
        d.fs.steps() + u64::try_from(sync).unwrap(),
        KagemushaWalletSimFaultV1::Error,
    );
    assert!(current.abandon_expired(&proof).is_err());
    d.fs.clear_faults();
    let before = d.fs.steps();
    assert_eq!(
        current.abandon().unwrap(),
        EnrollmentAbandonmentV1::LocalAbandoned
    );
    assert!(
        d.fs.trace_since(before)
            .contains(&KagemushaWalletSimStepV1::SyncDir)
    );
    drop(current);
    d.fs.restart();
    let mut current = owner(&f, &d);
    dispatch(&f, &mut current);
    assert_eq!(current.abandonment_ledger_instruction().unwrap(), None);
    d.platform.with(|s| assert_eq!(s.generate_calls, 0));
}
