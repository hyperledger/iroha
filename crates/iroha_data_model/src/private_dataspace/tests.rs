//! Genuine native private-root certificate fixtures and hostile parent-anchor inputs.

use super::*;
use crate::sumeragi_finality::{authenticated_genesis, test_fixtures::NativeFinalityFixture};
use iroha_crypto::{Hash, HashOf};

fn fixture() -> (NativeFinalityFixture, PrivateDataspaceRegistration) {
    let scope = SumeragiRootScope::Dataspace {
        parent_network_id: NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
            b"private anchor parent",
        ))),
        dataspace_id: DataSpaceId::new(u64::MAX),
    };
    let fixture = NativeFinalityFixture::start_with_scope("private-anchor", scope);
    let verified = fixture
        .verifier()
        .verify_retained_decision(fixture.genesis_proof())
        .unwrap();
    let registration = PrivateDataspaceRegistration::new(
        scope,
        fixture.chain_id().parse().unwrap(),
        fixture.network_id(),
        verified.result().0,
        authenticated_genesis(fixture.genesis())
            .map(|genesis| genesis.into_parts().0)
            .unwrap(),
    )
    .unwrap();
    (fixture, registration)
}

fn next(
    fixture: &mut NativeFinalityFixture,
    registration: &PrivateDataspaceRegistration,
) -> PrivateDataspaceAnchor {
    let block = fixture.block_with_submitted_work(fixture.next_header());
    let proof = fixture.certify(block);
    let verified = fixture.verifier().verify_retained_decision(&proof).unwrap();
    PrivateDataspaceAnchor::from_certificate(
        registration,
        verified.block().commit_certificate().unwrap(),
    )
    .unwrap()
}

#[test]
fn signed_private_anchors_extend_and_replay_without_exporting_body() {
    let (mut fixture, registration) = fixture();
    let encoded = norito::encode_canonical(&registration).unwrap();
    assert_eq!(
        norito::decode_canonical::<PrivateDataspaceRegistration>(&encoded).unwrap(),
        registration
    );
    assert_eq!(
        PrivateDataspaceRegistration::decode(&encoded).unwrap(),
        registration
    );
    assert!(
        PrivateDataspaceRegistration::decode(&vec![
            0;
            MAX_PRIVATE_DATASPACE_REGISTRATION_BYTES + 1
        ])
        .is_err()
    );
    let mut state =
        PrivateDataspaceAnchorState::from_authorized_registration(registration.clone()).unwrap();
    assert_eq!(state.registration(), &registration);
    assert_eq!(state.cursor(), registration.genesis_cursor);
    let anchor = next(&mut fixture, &registration);
    assert_eq!(anchor.height().unwrap(), 2);
    let mut malformed_height = anchor.clone();
    malformed_height.certificate.consensus_header.clear();
    assert!(malformed_height.height().is_err());
    let encoded = norito::encode_canonical(&anchor).unwrap();
    assert_eq!(PrivateDataspaceAnchor::decode(&encoded).unwrap(), anchor);
    assert!(
        !encoded
            .windows(b"fixture submitted work".len())
            .any(|window| window == b"fixture submitted work")
    );
    assert_eq!(
        state.apply(&anchor).unwrap(),
        PrivateDataspaceAnchorOutcome::Advanced
    );
    assert_eq!(state.cursor().height, 2);
    let retained = state.clone();
    assert_eq!(
        state.apply(&anchor).unwrap(),
        PrivateDataspaceAnchorOutcome::AlreadyAnchored
    );
    assert_eq!(state, retained);
    let encoded = norito::encode_canonical(&state).unwrap();
    assert_eq!(
        norito::decode_canonical::<PrivateDataspaceAnchorState>(&encoded).unwrap(),
        state
    );
    let second = next(&mut fixture, &registration);
    assert_eq!(
        state.apply(&second).unwrap(),
        PrivateDataspaceAnchorOutcome::Advanced
    );
    assert!(state.apply(&anchor).is_err());
}

#[test]
fn genuine_conflicts_gaps_and_foreign_bindings_do_not_change_parent_state() {
    let (mut fixture, registration) = fixture();
    let first = next(&mut fixture, &registration);
    let second = next(&mut fixture, &registration);
    let mut state =
        PrivateDataspaceAnchorState::from_authorized_registration(registration.clone()).unwrap();
    let genesis = state.clone();
    assert!(state.apply(&second).is_err());
    assert_eq!(state, genesis);
    state.apply(&first).unwrap();
    let retained = state.clone();
    let mut foreign = second.clone();
    foreign.dataspace_id = DataSpaceId::new(u64::from(u32::MAX));
    assert!(state.apply(&foreign).is_err());
    foreign = second.clone();
    foreign.parent_network_id = registration.child_network_id;
    assert!(state.apply(&foreign).is_err());
    foreign = second.clone();
    foreign.child_network_id = first.parent_network_id;
    assert!(state.apply(&foreign).is_err());
    assert_eq!(state, retained);

    // A genuinely quorum-signed alternate H2 still cannot replace the retained decision.
    let (mut alternate, _) = self::fixture();
    let mut header = alternate.next_header();
    header.creation_time_ms += 1;
    let block = alternate.block_with_submitted_work(header);
    let proof = alternate.certify(block);
    let verified = alternate
        .verifier()
        .verify_retained_decision(&proof)
        .unwrap();
    let conflict = PrivateDataspaceAnchor::from_certificate(
        &registration,
        verified.block().commit_certificate().unwrap(),
    )
    .unwrap();
    assert!(state.apply(&conflict).is_err());
    assert_eq!(state, retained);
}

#[test]
fn opaque_export_refuses_control_private_sidecars_and_resource_overflow() {
    use iroha_sumeragi::types::ControlWitness;
    let (mut fixture, registration) = fixture();
    let anchor = next(&mut fixture, &registration);
    let mut secret = anchor.clone();
    let mut header: CoreHeader =
        norito::decode_canonical(&secret.certificate.consensus_header).unwrap();
    header.control_witness = ControlWitness::try_from_slice(b"private contract source").unwrap();
    secret.certificate.consensus_header = norito::encode_canonical(&header).unwrap();
    assert!(secret.public_parts().is_err());
    assert!(PrivateDataspaceAnchor::decode(&norito::encode_canonical(&secret).unwrap()).is_err());
    let mut secret = anchor.clone();
    // The current certificate has no opaque witness field. A private body
    // appended to its exact canonical frame is rejected before export.
    secret
        .certificate
        .commit_qc
        .extend_from_slice(b"private transaction body");
    assert!(secret.public_parts().is_err());
    let mut too_large = anchor.clone();
    too_large
        .certificate
        .result_preimage
        .resize(MAX_RESULT_PREIMAGE_BYTES + 1, 0);
    assert!(too_large.public_parts().is_err());
    assert!(bounds(&[], &[], &[]).is_err());
    assert!(
        PrivateDataspaceAnchor::decode(&vec![0; MAX_PRIVATE_DATASPACE_ANCHOR_BYTES + 1]).is_err()
    );
    let mut trailing = norito::encode_canonical(&anchor).unwrap();
    trailing.push(0);
    assert!(PrivateDataspaceAnchor::decode(&trailing).is_err());
}

#[test]
fn bad_quorum_parent_and_result_are_rejected_without_partial_progress() {
    let (mut fixture, registration) = fixture();
    let anchor = next(&mut fixture, &registration);
    let mut state =
        PrivateDataspaceAnchorState::from_authorized_registration(registration).unwrap();
    let original = state.clone();
    let mut changed = anchor.clone();
    let mut qc: Qc = norito::decode_canonical(&changed.certificate.commit_qc).unwrap();
    qc.agg_sig.0[0] ^= 1;
    changed.certificate.commit_qc = norito::encode_canonical(&qc).unwrap();
    assert!(state.apply(&changed).is_err());
    let mut changed = anchor.clone();
    let mut header: CoreHeader =
        norito::decode_canonical(&changed.certificate.consensus_header).unwrap();
    header.parent_result.0[0] ^= 1;
    changed.certificate.consensus_header = norito::encode_canonical(&header).unwrap();
    assert!(state.apply(&changed).is_err());
    let mut changed = anchor.clone();
    let (original_x, mut result) = CertifiedResultV1::decode(
        &changed.certificate.result_preimage,
        crate::sumeragi_finality::CertifiedResultScope::NonGlobal,
    )
    .unwrap()
    .into_parts();
    result.execution.world_state_root = Hash::new(b"unrelated state");
    changed.certificate.result_preimage =
        CertifiedResultV1::from_parts_unvalidated(original_x, result)
            .preimage()
            .unwrap();
    assert!(state.apply(&changed).is_err());
    assert_eq!(state, original);
    state.apply(&anchor).unwrap();
}

#[test]
fn registration_requires_exact_private_genesis_and_fixed_permissioned_authority() {
    let (_, registration) = fixture();
    let mut invalid = registration.clone();
    invalid.scope = SumeragiRootScope::Global;
    assert!(invalid.validate().is_err());
    invalid = registration.clone();
    invalid.scope = SumeragiRootScope::Dataspace {
        parent_network_id: registration.child_network_id,
        dataspace_id: DataSpaceId::new(1),
    };
    assert!(invalid.validate().is_err());
    invalid = registration.clone();
    invalid.scope = SumeragiRootScope::Dataspace {
        parent_network_id: registration.parent_scope().unwrap().0,
        dataspace_id: DataSpaceId::UNIVERSAL,
    };
    assert!(invalid.validate().is_err());
    invalid = registration.clone();
    invalid.genesis_cursor.consensus_hash[0] ^= 1;
    assert!(invalid.validate().is_err());
    invalid = registration.clone();
    invalid.child_chain_id = "another-private-chain".parse().unwrap();
    assert!(invalid.validate().is_err());
    invalid = registration.clone();
    invalid.instance[0] ^= 1;
    assert!(invalid.validate().is_err());
    invalid = registration.clone();
    invalid.initial_epoch.authorization.last_height = 10;
    assert!(invalid.validate().is_err());
    invalid = registration.clone();
    invalid.initial_epoch.mode = ConsensusMode::Npos;
    assert!(invalid.validate().is_err());
    invalid = registration.clone();
    invalid.initial_epoch.committee.pop();
    assert!(invalid.validate().is_err());
    assert!(
        private_instance(
            registration.scope,
            registration.child_network_id,
            &registration.child_chain_id,
            &invalid.initial_epoch
        )
        .is_err()
    );
}

#[test]
fn authenticated_anchor_state_json_roundtrip_and_restore_invariants() {
    let (mut fixture, registration) = fixture();
    let mut state =
        PrivateDataspaceAnchorState::from_authorized_registration(registration.clone()).unwrap();
    state.validate().unwrap();
    let genesis = state.clone();
    let anchor = next(&mut fixture, &registration);
    let json = norito::json::to_json(&anchor).unwrap();
    assert_eq!(
        norito::json::from_str::<PrivateDataspaceAnchor>(&json).unwrap(),
        anchor
    );
    state.apply(&anchor).unwrap();
    let json = norito::json::to_json(&state).unwrap();
    let restored: PrivateDataspaceAnchorState = norito::json::from_str(&json).unwrap();
    restored.validate().unwrap();
    assert_eq!(restored, state);
    for field in 0..6 {
        let mut malformed = genesis.clone();
        match field {
            0 => malformed.cursor.height = 0,
            1 => malformed.cursor.result = [0; 32],
            2 => malformed.cursor.consensus_hash = [1; 32],
            3 => malformed.tracker.instance = [1; 32],
            4 => malformed.tracker.result_scope = CertifiedResultScope::TairaGlobal,
            _ => malformed.tracker.previous = Some(registration.initial_epoch.clone()),
        }
        assert!(malformed.validate().is_err());
        let before = malformed.clone();
        assert!(malformed.apply(&anchor).is_err());
        assert_eq!(malformed, before);
    }
}

#[test]
fn private_anchor_rejects_bare_body_and_active_x_without_advancing() {
    use crate::sumeragi_finality::certified_result::FLAG_ACTIVE;
    use crate::sumeragi_finality::{SccpFinalityHeaderV1, context_committee_root};
    let (mut fixture, registration) = fixture();
    let anchor = next(&mut fixture, &registration);
    let mut state =
        PrivateDataspaceAnchorState::from_authorized_registration(registration).unwrap();
    let retained = state.clone();
    let result = CertifiedResultV1::decode(
        &anchor.certificate.result_preimage,
        CertifiedResultScope::NonGlobal,
    )
    .unwrap();
    let mut bare = anchor.clone();
    bare.certificate.result_preimage = result.commitment().preimage().unwrap();
    assert!(matches!(
        bare.public_parts(),
        Err(PrivateDataspaceAnchorError::Invalid(_))
    ));
    assert!(state.apply(&bare).is_err());
    let mut fields = result.header().fields();
    fields.flags = FLAG_ACTIVE;
    fields.generation = 1;
    fields.committee_root = context_committee_root(&result.commitment().schedule.current).unwrap();
    let active = CertifiedResultV1::new(
        SccpFinalityHeaderV1::from_fields(&fields).unwrap(),
        result.commitment().clone(),
        CertifiedResultScope::TairaGlobal,
    )
    .unwrap();
    let mut wrong_scope = anchor.clone();
    wrong_scope.certificate.result_preimage = active.preimage().unwrap();
    assert!(matches!(
        wrong_scope.public_parts(),
        Err(PrivateDataspaceAnchorError::Invalid(_))
    ));
    assert!(
        PrivateDataspaceAnchor::decode(&norito::encode_canonical(&wrong_scope).unwrap()).is_err()
    );
    assert!(state.apply(&wrong_scope).is_err());
    assert_eq!(state, retained);
    assert_eq!(
        state.apply(&anchor).unwrap(),
        PrivateDataspaceAnchorOutcome::Advanced
    );
}

#[test]
fn private_anchor_local_decoder_refusal_preserves_original_and_retries() {
    let (mut fixture, registration) = fixture();
    let anchor = next(&mut fixture, &registration);
    let original = anchor.clone();
    let mut state =
        PrivateDataspaceAnchorState::from_authorized_registration(registration).unwrap();
    let retained = state.clone();
    let limit =
        norito::DecodeLimits::new(96, MAX_PRIVATE_DATASPACE_ANCHOR_BYTES, usize::MAX, 0, 32);
    let error = norito::with_decode_limits_scope(limit, || state.apply(&anchor)).unwrap_err();
    assert!(
        matches!(error, PrivateDataspaceAnchorError::Resource(_)),
        "{error:?}"
    );
    assert_eq!(state, retained);
    assert_eq!(anchor, original);
    let bytes = norito::encode_canonical(&anchor).unwrap();
    let error = norito::with_decode_limits_scope(limit, || PrivateDataspaceAnchor::decode(&bytes))
        .unwrap_err();
    assert!(
        matches!(error, PrivateDataspaceAnchorError::Resource(_)),
        "{error:?}"
    );
    assert_eq!(PrivateDataspaceAnchor::decode(&bytes).unwrap(), original);
    assert_eq!(
        state.apply(&anchor).unwrap(),
        PrivateDataspaceAnchorOutcome::Advanced
    );
}

#[test]
fn private_anchor_resource_mapping_preserves_nested_and_intrinsic_categories() {
    use crate::sumeragi_finality::{CertifiedResultError, CommitmentError};
    let allocation = || {
        norito::core::classify_decode_attempt(|| {
            Err::<(), _>(norito::Error::AllocationFailed { bytes: 221 })
        })
        .unwrap_err()
    };
    for route in 0..2 {
        let original = allocation();
        let expected = original.local_refusal().unwrap();
        let converted = if route == 0 {
            certified_failure(CertifiedResultError::Body(CommitmentError::Resource(
                original,
            )))
        } else {
            amx_failure(crate::sumeragi_amx::AmxError::Resource(original))
        };
        let PrivateDataspaceAnchorError::Resource(retained) = converted else {
            panic!("original refusal must retain its category");
        };
        assert_eq!(retained.local_refusal(), Some(expected));
    }
    assert!(matches!(
        codec_failure(allocation()),
        PrivateDataspaceAnchorError::Resource(_)
    ));
    assert!(matches!(
        certified_failure(CertifiedResultError::ActiveOutsideGlobal),
        PrivateDataspaceAnchorError::Invalid(_)
    ));
    for cause in [
        norito::Error::InvalidMagic,
        norito::Error::SequenceLengthExceeded {
            length: 97,
            limit: 96,
        },
    ] {
        let error = norito::core::classify_decode_attempt(|| Err::<(), _>(cause)).unwrap_err();
        assert!(matches!(
            codec_failure(error),
            PrivateDataspaceAnchorError::Invalid(_)
        ));
    }
    // An enclosing owner does not turn an intrinsic protocol limit into local refusal.
    let limits = |bytes| norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, 64);
    for enclosing in [8, 16] {
        let error = norito::with_decode_limits_scope(limits(enclosing), || {
            norito::core::classify_decode_attempt(|| {
                norito::with_decode_limits_scope(limits(8), || {
                    norito::core::reserve_decode_allocation(9)
                })
            })
        })
        .unwrap_err();
        assert!(matches!(
            codec_failure(error),
            PrivateDataspaceAnchorError::Invalid(_)
        ));
    }
}
