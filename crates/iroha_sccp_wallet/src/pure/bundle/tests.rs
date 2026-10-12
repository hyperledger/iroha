//! Actual current-suite bundle, checkpoint, committee and proof refusal controls.

use super::*;
use crate::pure::test_support::{Fixture, INSTANCE, NETWORK, NOW};
use iroha_sccp::v1::committee::IDENTITY_SIGNATURE;

fn context(f: &Fixture, flavor: DestinationFlavor) -> DestinationContextV1<'_> {
    DestinationContextV1 {
        taira_network_id: NETWORK,
        consensus_instance: INSTANCE,
        destination: f.destination,
        flavor,
        committee_state: f.state,
        ton_keys: (flavor == DestinationFlavor::Ton).then_some(f.keys.as_slice()),
        checkpoints: &f.checkpoints,
        now_ms: NOW,
    }
}

#[test]
fn current_direct_and_history_bundles_preserve_original_authority_and_payload() {
    let fixture = Fixture::new();
    for flavor in [DestinationFlavor::Evm, DestinationFlavor::Ton] {
        for bundle in [fixture.message(), fixture.historical_message()] {
            let verified = verify_message_bundle(
                &bundle,
                &context(&fixture, flavor),
                BundlePurposeV1::Finalize,
                CertificateUseV1::Inline,
            )
            .unwrap();
            assert_eq!(verified.is_historical(), bundle.is_historical());
            assert!(!verified.is_checkpoint());
            assert_eq!(verified.nonce(), 1);
            assert_eq!(verified.deadline_ms(), bundle.deadline_ms);
            assert_eq!(verified.transfer().message_id, bundle.message_id);
            assert_eq!(verified.header().as_bytes(), &bundle.certificate.header);
            assert_eq!(verified.proof, bundle.message_proof());
        }
    }
}

#[test]
fn candidates_cannot_replace_destination_identity_keys_or_committee_state() {
    let fixture = Fixture::new();
    let other = Fixture::with_tag(1);
    let bundle = fixture.message();
    for flavor in [DestinationFlavor::Evm, DestinationFlavor::Ton] {
        let selected = context(&fixture, flavor);
        let mut wrong = selected;
        wrong.taira_network_id[0] ^= 1;
        assert_eq!(
            verify_certificate_bundle(&bundle.certificate, &wrong, CertificateUseV1::Inline),
            Err(BundleError::HeaderMismatch)
        );
        wrong = selected;
        wrong.consensus_instance[0] ^= 1;
        assert!(
            verify_certificate_bundle(&bundle.certificate, &wrong, CertificateUseV1::Inline)
                .is_err()
        );
        wrong = selected;
        wrong.committee_state = other.state;
        assert!(
            verify_certificate_bundle(&bundle.certificate, &wrong, CertificateUseV1::Inline)
                .is_err()
        );
        wrong = selected;
        wrong.committee_state.generation += 1;
        assert!(
            verify_certificate_bundle(&bundle.certificate, &wrong, CertificateUseV1::Inline)
                .is_err()
        );
        wrong = selected;
        wrong.committee_state.until_ms = NOW - 1;
        assert_eq!(
            verify_certificate_bundle(&bundle.certificate, &wrong, CertificateUseV1::Inline),
            Err(BundleError::Certificate(
                DestinationError::CommitteeNotAccepted
            ))
        );
        wrong = selected;
        wrong.committee_state.equivocated = true;
        assert_eq!(
            verify_certificate_bundle(&bundle.certificate, &wrong, CertificateUseV1::Inline),
            Err(BundleError::Certificate(DestinationError::Equivocated))
        );
        let mut candidate = bundle.certificate.clone();
        candidate.committee = other.keys.clone();
        assert_eq!(
            verify_certificate_bundle(&candidate, &selected, CertificateUseV1::Inline),
            Err(BundleError::Shape(ApiShapeError::CommitteeRootMismatch))
        );
        candidate = bundle.certificate.clone();
        candidate.aggregate_signature = other.message().certificate.aggregate_signature;
        assert_eq!(
            verify_certificate_bundle(&candidate, &selected, CertificateUseV1::Inline),
            Err(BundleError::Certificate(DestinationError::BadSignature))
        );
        candidate.aggregate_signature = IDENTITY_SIGNATURE;
        assert!(
            verify_certificate_bundle(&candidate, &selected, CertificateUseV1::Inline).is_err()
        );
        candidate = bundle.certificate.clone();
        candidate.qc[112..116].copy_from_slice(&15_u32.to_be_bytes());
        assert_eq!(
            verify_certificate_bundle(&candidate, &selected, CertificateUseV1::Inline),
            Err(BundleError::Shape(ApiShapeError::BadSignerSet))
        );
    }
    let mut wrong = context(&fixture, DestinationFlavor::Ton);
    wrong.ton_keys = Some(&other.keys);
    assert_eq!(
        verify_certificate_bundle(&bundle.certificate, &wrong, CertificateUseV1::Inline),
        Err(BundleError::Certificate(DestinationError::BadCommittee))
    );
    wrong.ton_keys = None;
    assert_eq!(
        verify_certificate_bundle(&bundle.certificate, &wrong, CertificateUseV1::Inline),
        Err(BundleError::Certificate(DestinationError::BadCommittee))
    );
}

#[test]
fn checkpoint_mode_requires_exact_stored_header_and_live_current_use_rule() {
    let mut fixture = Fixture::new();
    let bundle = fixture.message();
    assert_eq!(
        verify_certificate_bundle(
            &bundle.certificate,
            &context(&fixture, DestinationFlavor::Evm),
            CertificateUseV1::Checkpoint
        ),
        Err(BundleError::Certificate(
            DestinationError::UnknownCheckpoint
        ))
    );
    fixture.checkpoints.insert(
        bundle.certificate.height,
        checkpoint_id(&bundle.certificate.header),
    );
    let selected = context(&fixture, DestinationFlavor::Evm);
    let verified = verify_message_bundle(
        &bundle,
        &selected,
        BundlePurposeV1::Finalize,
        CertificateUseV1::Checkpoint,
    )
    .unwrap();
    assert!(verified.is_checkpoint());
    let mut candidate = bundle.certificate.clone();
    candidate.aggregate_signature = [0; 96];
    // The stored id is the authority here; no inline signature fallback is needed or used.
    assert!(verify_certificate_bundle(&candidate, &selected, CertificateUseV1::Checkpoint).is_ok());
    assert!(verify_certificate_bundle(&candidate, &selected, CertificateUseV1::Inline).is_err());
    let mut foreign = selected;
    foreign.committee_state.generation += 1;
    foreign.committee_state.start = 10;
    assert_eq!(
        verify_certificate_bundle(&candidate, &foreign, CertificateUseV1::Checkpoint),
        Err(BundleError::Certificate(
            DestinationError::CommitteeNotAccepted
        ))
    );
    foreign = selected;
    foreign.committee_state.until_ms = NOW - 1;
    assert_eq!(
        verify_certificate_bundle(&candidate, &foreign, CertificateUseV1::Checkpoint),
        Err(BundleError::Certificate(
            DestinationError::CommitteeNotAccepted
        ))
    );
    foreign = selected;
    foreign.committee_state.equivocated = true;
    assert_eq!(
        verify_certificate_bundle(&candidate, &foreign, CertificateUseV1::Checkpoint),
        Err(BundleError::Certificate(DestinationError::Equivocated))
    );
    let mut other_header = fixture.fields(9);
    other_header.timestamp_ms += 1;
    let other = fixture.certify(other_header);
    assert_eq!(
        verify_certificate_bundle(&other, &selected, CertificateUseV1::Checkpoint),
        Err(BundleError::Certificate(
            DestinationError::UnknownCheckpoint
        ))
    );
}

#[test]
fn tampered_paths_payloads_and_redundant_deadlines_fail() {
    let fixture = Fixture::new();
    let selected = context(&fixture, DestinationFlavor::Evm);
    let original = fixture.message();
    for mutate in [
        |b: &mut SccpMessageProofBundleV1| b.path[0][0] ^= 1,
        |b: &mut SccpMessageProofBundleV1| b.leaf_index = 0,
        |b: &mut SccpMessageProofBundleV1| b.payload[0] ^= 1,
        |b: &mut SccpMessageProofBundleV1| b.block.sccp_root[0] ^= 1,
        |b: &mut SccpMessageProofBundleV1| b.block.height += 1,
        |b: &mut SccpMessageProofBundleV1| b.block.message_count += 1,
    ] {
        let mut changed = original.clone();
        mutate(&mut changed);
        assert!(matches!(
            verify_message_bundle(
                &changed,
                &selected,
                BundlePurposeV1::Finalize,
                CertificateUseV1::Inline
            ),
            Err(BundleError::Proof(_))
        ));
    }
    let mut changed = original.clone();
    changed.message_id[0] ^= 1;
    assert_eq!(
        verify_message_bundle(
            &changed,
            &selected,
            BundlePurposeV1::Finalize,
            CertificateUseV1::Inline
        ),
        Err(BundleError::MessageIdMismatch)
    );
    changed = original.clone();
    changed.deadline_ms += 1;
    assert_eq!(
        verify_message_bundle(
            &changed,
            &selected,
            BundlePurposeV1::Finalize,
            CertificateUseV1::Inline
        ),
        Err(BundleError::DeadlineMismatch)
    );
    changed = fixture.historical_message();
    changed.block.history_path[0][0] ^= 1;
    assert_eq!(
        verify_message_bundle(
            &changed,
            &selected,
            BundlePurposeV1::Finalize,
            CertificateUseV1::Inline
        ),
        Err(BundleError::Proof(ProofError::BadBlockReference))
    );
    let mut foreign = selected;
    foreign.destination.destination_word[31] ^= 1;
    assert_eq!(
        verify_message_bundle(
            &original,
            &foreign,
            BundlePurposeV1::Finalize,
            CertificateUseV1::Inline
        ),
        Err(BundleError::Proof(ProofError::BadBlockPath))
    );
    foreign = selected;
    foreign.destination.route_revision += 1;
    assert_eq!(
        verify_message_bundle(
            &original,
            &foreign,
            BundlePurposeV1::Finalize,
            CertificateUseV1::Inline
        ),
        Err(BundleError::Proof(ProofError::WrongDestination))
    );
}

#[test]
fn deadline_equality_allows_finalize_and_refuses_void() {
    assert_eq!(check_deadline(BundlePurposeV1::Finalize, 42, 42), Ok(()));
    assert_eq!(
        check_deadline(BundlePurposeV1::Finalize, 42, 43),
        Err(BundleError::DeadlinePassed)
    );
    assert_eq!(
        check_deadline(BundlePurposeV1::VoidExpired, 42, 42),
        Err(BundleError::DeadlineNotReached)
    );
    assert_eq!(check_deadline(BundlePurposeV1::VoidExpired, 42, 43), Ok(()));
}
