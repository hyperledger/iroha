//! Provider marker, output descriptor, recovery capsule, completion record and fold record
//! tests.

use super::*;
use crate::kagemusha::kagemusha_wallet_v1::{
    KagemushaWalletEvidenceKindV1, KagemushaWalletLifecycleV1, KagemushaWalletReceiptBodyV1,
    KagemushaWalletReceiptSignerV1, KagemushaWalletValidationErrorV1,
    codec_tests::norito_tag,
    identity::identity_tests::{IdentityFixture, identity_fixture, raw_output},
    kagemusha_wallet_unload_nullifier_v1,
    messages::messages_tests::message_fixture,
    state::state_tests::{
        bootstrap_statement, commitment, field_value, lineage_for, send_effect, stand_in_proof,
        transition_statement,
    },
};

/// One mutation of a recovery capsule.
type CapsuleMutation = fn(&mut KagemushaWalletRecoveryCapsuleV1);

fn android() -> IdentityFixture {
    identity_fixture(KagemushaWalletEvidenceKindV1::AndroidKeyMintTee, 0x65)
}

#[track_caller]
fn assert_invalid<T: core::fmt::Debug>(result: WalletResult<T>, expected: &str) {
    match result {
        Err(KagemushaWalletValidationErrorV1::InvalidField { field }) if field == expected => {}
        other => panic!("expected invalid `{expected}`, got {other:?}"),
    }
}

fn enrollment_marker(f: &IdentityFixture) -> KagemushaWalletMarkerV1 {
    KagemushaWalletMarkerV1::enrollment(&f.challenge, f.credential.body.payment_key)
        .expect("enrollment marker")
}

/// The fold-witness inputs a capsule of `kind` must retain, with stand-in bytes.
fn retained_for(kind: KagemushaWalletOperationKindV1) -> Vec<KagemushaWalletRetainedInputV1> {
    required_retained_roles_v1(kind)
        .iter()
        .map(|role| KagemushaWalletRetainedInputV1 {
            role: *role,
            bytes: vec![0xa0 | role.tag(); 16],
        })
        .collect()
}

/// Recovery capsule of `statement` with `lineage`, `step_proof` and `payment_digest` under
/// `credential`, with a successor state that agrees with the statement.
///
/// The statement's stand-in successor seeds the successor state's nonce and is then replaced by
/// that state's computed commitment, which a valid capsule binds.
fn capsule_with(
    credential: &KagemushaWalletCredentialV1,
    statement: &KagemushaWalletStatementV1,
    lineage: KagemushaWalletLineageSlotV1,
    step_proof: KagemushaWalletStepProofV1,
    payment_digest: [u8; 32],
    predecessor_capsule_digest: [u8; 32],
) -> KagemushaWalletRecoveryCapsuleV1 {
    let mut state =
        KagemushaWalletStateV1::bootstrap(credential, statement.successor.value).expect("state");
    state.core.sequence = statement.sequence;
    state.core.next_load = statement.next_load;
    state.core.lifecycle = statement.lifecycle;
    state.core.burned_total = statement.lineage_burned_total;
    let statement = &KagemushaWalletStatementV1 {
        successor: state.commitment().expect("successor commitment"),
        ..*statement
    };
    let kind = statement.effect.kind();
    let proof_digest = kagemusha_wallet_proof_digest_v1(kind, lineage.lineage(), &step_proof)
        .expect("proof digest");
    let output = KagemushaWalletOutputDescriptorV1::for_transition(
        statement,
        &proof_digest,
        &payment_digest,
    )
    .expect("output");
    KagemushaWalletRecoveryCapsuleV1 {
        version: KAGEMUSHA_WALLET_VERSION_V1,
        scheme_id: credential.body.scheme_id,
        wallet_id: credential.body.wallet_id,
        operation_id: statement.operation_id(&credential.body.wallet_id),
        kind,
        predecessor_capsule_digest,
        successor_state: state,
        statement: *statement,
        predecessor_lineage: lineage,
        step_proof,
        payment_digest,
        map_openings: vec![vec![0x01, 0x02, 0x03]],
        retained_inputs: retained_for(kind),
        output,
    }
}

/// Capsule of `statement` with the generic stand-ins: Ω(pred) exactly when the operation
/// consumes it, and a Receive Payment digest of `0x63`.
fn capsule_for(
    credential: &KagemushaWalletCredentialV1,
    statement: &KagemushaWalletStatementV1,
    step_proof: KagemushaWalletStepProofV1,
    predecessor_capsule_digest: [u8; 32],
) -> KagemushaWalletRecoveryCapsuleV1 {
    let kind = statement.effect.kind();
    let lineage = if kind.consumes_lineage() {
        KagemushaWalletLineageSlotV1::Present {
            lineage: lineage_for(credential, statement),
        }
    } else {
        KagemushaWalletLineageSlotV1::None
    };
    let payment = if kind == KagemushaWalletOperationKindV1::Receive {
        field_value(0x63)
    } else {
        [0; 32]
    };
    capsule_with(
        credential,
        statement,
        lineage,
        step_proof,
        payment,
        predecessor_capsule_digest,
    )
}

/// Receipt over `capsule`'s digest and the released package.
fn complete(
    f: &IdentityFixture,
    credential: &KagemushaWalletCredentialV1,
    capsule: &KagemushaWalletRecoveryCapsuleV1,
) -> (KagemushaWalletReceiptV1, KagemushaWalletPackageV1) {
    let digest = capsule.capsule_digest().expect("capsule digest");
    let proof_digest = capsule.proof_digest().expect("proof digest");
    let signer = KagemushaWalletReceiptSignerV1::from_credential(credential).expect("signer");
    let body = KagemushaWalletReceiptBodyV1::derive(
        &signer,
        &capsule.statement,
        &proof_digest,
        digest,
        capsule.payment_digest,
    )
    .expect("receipt body");
    let receipt = KagemushaWalletReceiptV1::sign(
        credential,
        &capsule.statement,
        &proof_digest,
        digest,
        capsule.payment_digest,
        raw_output(&f.payment, &body.signing_message()),
    )
    .expect("receipt");
    let package = KagemushaWalletPackageV1::new(
        capsule.statement,
        capsule.predecessor_lineage.clone(),
        capsule.step_proof.clone(),
        receipt,
    );
    (receipt, package)
}

/// Bootstrap capsule bound to `f`'s generation-0 enrollment marker.
fn bootstrap_capsule(f: &IdentityFixture) -> KagemushaWalletRecoveryCapsuleV1 {
    let statement = KagemushaWalletStatementV1 {
        effect: enrollment_marker(f)
            .bootstrap_effect()
            .expect("bootstrap effect"),
        ..bootstrap_statement(f)
    };
    capsule_for(&f.credential, &statement, stand_in_proof(48), [0; 32])
}

#[test]
fn kagemusha_wallet_v1_custody_layouts_and_tags() {
    use KagemushaWalletRetainedInputRoleV1 as R;

    assert_eq!(KAGEMUSHA_WALLET_OUTPUT_TRANSCRIPT_BYTES_V1, 97);
    let transcript = kagemusha_wallet_output_transcript_v1(
        KagemushaWalletOperationKindV1::Receive,
        &[1; 32],
        &[2; 32],
        &[3; 32],
    );
    assert_eq!(
        transcript.len(),
        KAGEMUSHA_WALLET_OUTPUT_TRANSCRIPT_BYTES_V1
    );
    assert_eq!(transcript[0], 4);
    assert_eq!(&transcript[1..33], &[1; 32]);
    assert_eq!(&transcript[33..65], &[2; 32]);
    assert_eq!(&transcript[65..], &[3; 32]);
    assert_eq!(
        kagemusha_wallet_output_digest_v1(
            KagemushaWalletOperationKindV1::Receive,
            &[1; 32],
            &[2; 32],
            &[3; 32]
        ),
        kagemusha_wallet_digest_v1(Role::Output, &transcript)
    );
    for reason in KagemushaWalletTerminalReasonV1::ALL {
        assert_eq!(norito_tag(&reason), u32::from(reason.tag()));
    }
    for role in KagemushaWalletRetainedInputRoleV1::ALL {
        assert_eq!(norito_tag(&role), u32::from(role.tag()));
    }
    let states = [
        KagemushaWalletMarkerStateV1::Enrollment {
            challenge_digest: [1; 32],
            enrollment_id: [2; 32],
        },
        KagemushaWalletMarkerStateV1::Head {
            sequence: 0,
            operation_id: [3; 32],
            head: commitment(1),
            capsule_digest: [4; 32],
            predecessor_capsule_digest: [0; 32],
        },
        KagemushaWalletMarkerStateV1::Terminal {
            reason: KagemushaWalletTerminalReasonV1::Abandoned,
            last_capsule_digest: [0; 32],
        },
    ];
    for (index, state) in states.iter().enumerate() {
        assert_eq!(usize::from(state.tag()), index + 1);
        assert_eq!(norito_tag(state), u32::from(state.tag()));
    }
    // Fold witnesses (§4.1, design §9.1).
    assert_eq!(
        required_retained_roles_v1(KagemushaWalletOperationKindV1::Receive),
        &[R::Request, R::Payment, R::CertificateSet, R::Credential]
    );
    assert_eq!(
        required_retained_roles_v1(KagemushaWalletOperationKindV1::ArchiveSent),
        &[R::Request, R::Payment, R::Credited]
    );
    assert_eq!(
        required_retained_roles_v1(KagemushaWalletOperationKindV1::Send),
        &[R::Request]
    );
    assert_eq!(
        required_retained_roles_v1(KagemushaWalletOperationKindV1::Load),
        &[R::LoadVoucher, R::CertificateSet]
    );
    assert_eq!(
        required_retained_roles_v1(KagemushaWalletOperationKindV1::RefreshPolicy),
        &[R::PolicyUpdate, R::CertificateSet]
    );
    for kind in [
        KagemushaWalletOperationKindV1::Bootstrap,
        KagemushaWalletOperationKindV1::Unload,
        KagemushaWalletOperationKindV1::Retiring,
    ] {
        assert!(required_retained_roles_v1(kind).is_empty(), "{kind:?}");
    }
}

#[test]
fn kagemusha_wallet_v1_enrollment_marker_and_bootstrap_effect() {
    let f = android();
    let marker = enrollment_marker(&f);
    marker.validate().expect("marker");
    assert_eq!(marker.generation, 0);
    assert_eq!(marker.wallet_id, f.credential.body.wallet_id);
    let frame = marker.to_canonical_bytes().expect("frame");
    assert!(frame.len() <= KAGEMUSHA_WALLET_MARKER_MAX_BYTES_V1);
    let digest = marker.marker_digest().expect("digest");
    assert_eq!(digest, kagemusha_wallet_digest_v1(Role::Marker, &frame));
    assert_eq!(
        marker.bootstrap_effect().expect("effect"),
        KagemushaWalletEffectV1::Bootstrap {
            enrollment_id: f.credential.body.enrollment_id,
            enrollment_marker: digest,
        }
    );
    // The Bootstrap statement binding this marker runs under the credential.
    bootstrap_capsule(&f)
        .statement
        .validate_for_credential(&f.credential)
        .expect("bootstrap statement");

    assert_eq!(
        KagemushaWalletMarkerV1::decode_canonical(&frame, &f.credential.body.scheme_id)
            .expect("decode"),
        marker
    );
    assert!(matches!(
        KagemushaWalletMarkerV1::decode_canonical(&frame, &[0x40; 32]),
        Err(KagemushaWalletValidationErrorV1::SchemeMismatch {
            field: "marker.scheme_id"
        })
    ));
    assert!(matches!(
        KagemushaWalletMarkerV1::decode_canonical(
            &vec![0; KAGEMUSHA_WALLET_MARKER_MAX_BYTES_V1 + 1],
            &f.credential.body.scheme_id
        ),
        Err(KagemushaWalletValidationErrorV1::EncodedSizeExceeded { .. })
    ));
    let version = KagemushaWalletMarkerV1 {
        version: 2,
        ..marker
    };
    assert!(matches!(
        KagemushaWalletMarkerV1::decode_canonical(
            &norito::encode_canonical(&version).expect("encode"),
            &f.credential.body.scheme_id
        ),
        Err(KagemushaWalletValidationErrorV1::UnsupportedVersion { .. })
    ));

    let KagemushaWalletMarkerStateV1::Enrollment {
        challenge_digest, ..
    } = marker.state
    else {
        panic!("enrollment state");
    };
    let generation = KagemushaWalletMarkerV1 {
        generation: 1,
        ..marker
    };
    assert_invalid(generation.validate(), "marker.generation");
    let enrollment_id = KagemushaWalletMarkerV1 {
        state: KagemushaWalletMarkerStateV1::Enrollment {
            challenge_digest,
            enrollment_id: [0x41; 32],
        },
        ..marker
    };
    assert_invalid(enrollment_id.validate(), "marker.enrollment_id");
    let wallet = KagemushaWalletMarkerV1 {
        wallet_id: [0x42; 32],
        ..marker
    };
    assert_invalid(wallet.validate(), "marker.wallet_id");
    let head = marker
        .successor(bootstrap_capsule(&f).head_marker_state().expect("head"))
        .expect("head marker");
    assert_invalid(head.bootstrap_effect(), "marker.state");
}

#[test]
fn kagemusha_wallet_v1_marker_generations_follow_the_provider_contract() {
    let f = android();
    let enrollment = enrollment_marker(&f);
    let bootstrap = bootstrap_capsule(&f);
    let head0 = enrollment
        .successor(bootstrap.head_marker_state().expect("head"))
        .expect("bootstrap head");
    head0
        .require_capsule(&bootstrap)
        .expect("bootstrap capsule");
    let bootstrap_digest = bootstrap.capsule_digest().expect("digest");
    let next = capsule_for(
        &f.credential,
        &transition_statement(&f, 1, 0, KagemushaWalletLifecycleV1::Active, send_effect()),
        stand_in_proof(32),
        bootstrap_digest,
    );
    let head1 = head0
        .successor(next.head_marker_state().expect("head"))
        .expect("next head");
    head1.require_capsule(&next).expect("next capsule");
    assert_invalid(head1.require_capsule(&bootstrap), "marker.capsule");
    let next_digest = next.capsule_digest().expect("digest");
    let deleted = head1
        .successor(KagemushaWalletMarkerStateV1::Terminal {
            reason: KagemushaWalletTerminalReasonV1::CustodyDeleted,
            last_capsule_digest: next_digest,
        })
        .expect("custody deleted");
    let abandoned = enrollment
        .successor(KagemushaWalletMarkerStateV1::Terminal {
            reason: KagemushaWalletTerminalReasonV1::Abandoned,
            last_capsule_digest: [0; 32],
        })
        .expect("abandoned");

    // Disallowed transitions.
    assert_invalid(
        enrollment.successor(next.head_marker_state().expect("head")),
        "marker.state",
    );
    assert_invalid(
        head0.successor(KagemushaWalletMarkerStateV1::Head {
            sequence: 1,
            operation_id: next.operation_id,
            head: next.statement.successor,
            capsule_digest: next_digest,
            predecessor_capsule_digest: [0x43; 32],
        }),
        "marker.state",
    );
    assert_invalid(
        head1.successor(KagemushaWalletMarkerStateV1::Terminal {
            reason: KagemushaWalletTerminalReasonV1::Abandoned,
            last_capsule_digest: [0; 32],
        }),
        "marker.state",
    );
    assert_invalid(
        head1.successor(KagemushaWalletMarkerStateV1::Terminal {
            reason: KagemushaWalletTerminalReasonV1::CustodyDeleted,
            last_capsule_digest: bootstrap_digest,
        }),
        "marker.state",
    );
    assert_invalid(
        enrollment.successor(KagemushaWalletMarkerStateV1::Terminal {
            reason: KagemushaWalletTerminalReasonV1::CustodyDeleted,
            last_capsule_digest: [0x44; 32],
        }),
        "marker.state",
    );
    for terminal in [deleted, abandoned] {
        assert_invalid(
            terminal.successor(KagemushaWalletMarkerStateV1::Terminal {
                reason: KagemushaWalletTerminalReasonV1::CustodyDeleted,
                last_capsule_digest: [0x45; 32],
            }),
            "marker.state",
        );
    }
    let skipped = KagemushaWalletMarkerV1 {
        generation: 3,
        ..head1
    };
    assert_invalid(skipped.validate_successor_of(&head0), "marker.generation");
    let mut other_key = head1;
    other_key.payment_key = identity_fixture(KagemushaWalletEvidenceKindV1::AppleAppAttest, 0x66)
        .credential
        .body
        .payment_key;
    assert_invalid(other_key.validate_successor_of(&head0), "marker.identity");

    // Self-contained head and terminal rules.
    let mut zero_generation = head0;
    zero_generation.generation = 0;
    assert_invalid(zero_generation.validate(), "marker.generation");
    let mut unlinked = head1;
    unlinked.state = KagemushaWalletMarkerStateV1::Head {
        sequence: 1,
        operation_id: next.operation_id,
        head: next.statement.successor,
        capsule_digest: next_digest,
        predecessor_capsule_digest: [0; 32],
    };
    assert_invalid(unlinked.validate(), "marker.predecessor_capsule_digest");
    for head in [
        KagemushaWalletStateCommitmentV1::ZERO,
        KagemushaWalletStateCommitmentV1 { value: [0xff; 32] },
    ] {
        let mut incomplete = head1;
        incomplete.state = KagemushaWalletMarkerStateV1::Head {
            sequence: 1,
            operation_id: next.operation_id,
            head,
            capsule_digest: next_digest,
            predecessor_capsule_digest: bootstrap_digest,
        };
        assert_invalid(incomplete.validate(), "marker.head");
    }
    let mut abandoned_with_capsule = abandoned;
    abandoned_with_capsule.state = KagemushaWalletMarkerStateV1::Terminal {
        reason: KagemushaWalletTerminalReasonV1::Abandoned,
        last_capsule_digest: [0x46; 32],
    };
    assert_invalid(
        abandoned_with_capsule.validate(),
        "marker.last_capsule_digest",
    );
}

#[test]
fn kagemusha_wallet_v1_output_descriptors_are_receipt_free() {
    let f = android();
    let proof = stand_in_proof(40);
    let body = &f.credential.body;
    let nullifier = kagemusha_wallet_unload_nullifier_v1(&body.scheme_id, &body.wallet_id, 0);
    let effects = [
        KagemushaWalletEffectV1::Load {
            voucher: [0x51; 32],
            load_ordinal: 0,
            amount: 10,
            online_charge: 0,
        },
        KagemushaWalletEffectV1::Receive {
            credit_id: field_value(0x52),
            payer_wallet_id: [0x53; 32],
            amount: 3,
        },
        KagemushaWalletEffectV1::ArchiveSent {
            credit_id: field_value(0x55),
            credited: field_value(0x56),
        },
        KagemushaWalletEffectV1::Unload {
            nullifier,
            redeem_ordinal: 0,
            amount: 5,
            online_charge: 0,
            charge_quote: [0; 32],
        },
        KagemushaWalletEffectV1::Retiring,
        send_effect(),
    ];
    for effect in effects {
        let lifecycle = if effect == KagemushaWalletEffectV1::Retiring {
            KagemushaWalletLifecycleV1::Retiring
        } else {
            KagemushaWalletLifecycleV1::Active
        };
        let next_load = match effect {
            KagemushaWalletEffectV1::Load { load_ordinal, .. } => load_ordinal + 1,
            _ => 0,
        };
        let statement = transition_statement(&f, 3, next_load, lifecycle, effect);
        let kind = effect.kind();
        let lineage = kind
            .consumes_lineage()
            .then(|| lineage_for(&f.credential, &statement));
        let proof_digest =
            kagemusha_wallet_proof_digest_v1(kind, lineage.as_ref(), &proof).expect("digest");
        let payment = if kind == KagemushaWalletOperationKindV1::Receive {
            field_value(0x54)
        } else {
            [0; 32]
        };
        let descriptor =
            KagemushaWalletOutputDescriptorV1::for_transition(&statement, &proof_digest, &payment)
                .expect("descriptor");
        assert_eq!(descriptor.kind, kind);
        assert_eq!(
            descriptor.digest,
            kagemusha_wallet_output_digest_v1(
                kind,
                &statement.statement_digest(),
                &proof_digest,
                &payment,
            )
        );
        // The Payment digest is present exactly for Receive.
        let flipped = if payment == [0; 32] {
            field_value(0x57)
        } else {
            [0; 32]
        };
        assert_invalid(
            KagemushaWalletOutputDescriptorV1::for_transition(&statement, &proof_digest, &flipped),
            "output.payment_digest",
        );
        assert_invalid(
            KagemushaWalletOutputDescriptorV1::for_transition(&statement, &[0; 32], &payment),
            "output.proof_digest",
        );
    }

    // A Send releases its compact Payment; its descriptor covers statement and Ω‖σ digest.
    let m = message_fixture();
    let payment = m.payment(true, 40);
    let statement = &payment.send.statement;
    let proof_digest = payment.send.proof_digest().expect("proof digest");
    let descriptor =
        KagemushaWalletOutputDescriptorV1::for_transition(statement, &proof_digest, &[0; 32])
            .expect("send descriptor");
    assert_eq!(
        descriptor.digest,
        kagemusha_wallet_output_digest_v1(
            KagemushaWalletOperationKindV1::Send,
            &statement.statement_digest(),
            &proof_digest,
            &[0; 32],
        )
    );
    assert_invalid(
        KagemushaWalletOutputDescriptorV1 {
            kind: KagemushaWalletOperationKindV1::Send,
            digest: [0; 32],
        }
        .validate(),
        "output.digest",
    );
}

#[test]
fn kagemusha_wallet_v1_recovery_capsule_rules() {
    let f = android();
    let capsule = capsule_for(
        &f.credential,
        &transition_statement(
            &f,
            3,
            0,
            KagemushaWalletLifecycleV1::Active,
            KagemushaWalletEffectV1::Receive {
                credit_id: field_value(0x61),
                payer_wallet_id: [0x62; 32],
                amount: 9,
            },
        ),
        stand_in_proof(64),
        [0x64; 32],
    );
    capsule.validate().expect("capsule");
    assert_eq!(
        capsule.proof_digest().expect("digest"),
        kagemusha_wallet_proof_digest_v1(
            KagemushaWalletOperationKindV1::Receive,
            None,
            &capsule.step_proof
        )
        .expect("digest")
    );
    assert_eq!(capsule.predecessor_lineage(), None);
    let frame = capsule.to_canonical_bytes().expect("frame");
    assert!(frame.len() <= KAGEMUSHA_WALLET_CAPSULE_MAX_BYTES_V1);
    assert_eq!(
        capsule.capsule_digest().expect("digest"),
        kagemusha_wallet_digest_v1(Role::Capsule, &frame)
    );
    assert_eq!(
        KagemushaWalletRecoveryCapsuleV1::decode_canonical(&frame, &f.credential.body.scheme_id)
            .expect("decode"),
        capsule
    );
    assert!(matches!(
        KagemushaWalletRecoveryCapsuleV1::decode_canonical(&frame, &[0x65; 32]),
        Err(KagemushaWalletValidationErrorV1::SchemeMismatch { .. })
    ));
    assert_eq!(
        capsule.head_marker_state().expect("head"),
        KagemushaWalletMarkerStateV1::Head {
            sequence: 3,
            operation_id: capsule.operation_id,
            head: capsule.statement.successor,
            capsule_digest: capsule.capsule_digest().expect("digest"),
            predecessor_capsule_digest: [0x64; 32],
        }
    );
    bootstrap_capsule(&f).validate().expect("bootstrap capsule");

    let mutations: [(CapsuleMutation, &str); 20] = [
        (
            |capsule| capsule.kind = KagemushaWalletOperationKindV1::Load,
            "capsule.kind",
        ),
        (
            |capsule| capsule.output.kind = KagemushaWalletOperationKindV1::Load,
            "capsule.output.kind",
        ),
        (
            |capsule| capsule.operation_id = [0x66; 32],
            "capsule.operation_id",
        ),
        (
            |capsule| capsule.successor_state.core.wallet_id = [0x67; 32],
            "capsule.successor_state.wallet_id",
        ),
        (
            |capsule| capsule.successor_state.core.credential_digest = [0x68; 32],
            "capsule.successor_state.credential_digest",
        ),
        (
            |capsule| capsule.successor_state.core.asset_digest = [0x69; 32],
            "capsule.successor_state.asset_digest",
        ),
        (
            |capsule| {
                capsule.successor_state.core.lifecycle = KagemushaWalletLifecycleV1::Retiring;
            },
            "capsule.successor_state.lifecycle",
        ),
        (
            |capsule| capsule.successor_state.core.sequence += 1,
            "capsule.successor_state.sequence",
        ),
        (
            |capsule| capsule.successor_state.core.next_load += 1,
            "capsule.successor_state.next_load",
        ),
        (
            |capsule| capsule.predecessor_capsule_digest = [0; 32],
            "capsule.predecessor_capsule_digest",
        ),
        (
            |capsule| capsule.payment_digest = [0; 32],
            "capsule.payment_digest",
        ),
        (
            |capsule| capsule.payment_digest = field_value(0x6c),
            "capsule.output.digest",
        ),
        // Payment digests are canonical σ-field values (owner answer Q9).
        (
            |capsule| capsule.payment_digest = [0x6c; 32],
            "capsule.payment_digest",
        ),
        // The statement's successor is the computed commitment of the carried state (Q10).
        (
            |capsule| capsule.successor_state.core.balance += 1,
            "capsule.successor_state.commitment",
        ),
        (
            |capsule| capsule.successor_state.rest.time_anchor = [0x6e; 32],
            "capsule.successor_state.commitment",
        ),
        (
            |capsule| capsule.output.digest = [0x6a; 32],
            "capsule.output.digest",
        ),
        (
            |capsule| capsule.map_openings.push(Vec::new()),
            "capsule.map_openings",
        ),
        (
            |capsule| capsule.retained_inputs[0].bytes.clear(),
            "capsule.retained_input",
        ),
        (
            |capsule| {
                capsule
                    .retained_inputs
                    .retain(|input| input.role != KagemushaWalletRetainedInputRoleV1::Payment);
            },
            "capsule.retained_inputs",
        ),
        (
            |capsule| {
                capsule.step_proof = stand_in_proof(0);
            },
            "step_proof.bytes",
        ),
    ];
    for (mutate, field) in mutations {
        let mut mutated = capsule.clone();
        mutate(&mut mutated);
        assert_invalid(mutated.validate(), field);
    }
    let mut with_lineage = capsule.clone();
    with_lineage.predecessor_lineage = KagemushaWalletLineageSlotV1::Present {
        lineage: lineage_for(
            &f.credential,
            &transition_statement(&f, 3, 0, KagemushaWalletLifecycleV1::Active, send_effect()),
        ),
    };
    assert_invalid(with_lineage.validate(), "lineage.slot");
    let mut bootstrap = bootstrap_capsule(&f);
    bootstrap.predecessor_capsule_digest = [0x6b; 32];
    assert_invalid(bootstrap.validate(), "capsule.predecessor_capsule_digest");
    let mut version = capsule;
    version.version = 2;
    assert!(matches!(
        version.validate(),
        Err(KagemushaWalletValidationErrorV1::UnsupportedVersion { .. })
    ));
}

#[test]
fn kagemusha_wallet_v1_capsule_consumes_the_recorded_lineage() {
    let f = android();
    let statement =
        transition_statement(&f, 3, 0, KagemushaWalletLifecycleV1::Active, send_effect());
    let capsule = capsule_for(&f.credential, &statement, stand_in_proof(64), [0x64; 32]);
    capsule.validate().expect("send capsule");
    let lineage = capsule.predecessor_lineage().expect("Ω(pred)").clone();
    assert_eq!(
        capsule.proof_digest().expect("digest"),
        kagemusha_wallet_proof_digest_v1(
            KagemushaWalletOperationKindV1::Send,
            Some(&lineage),
            &capsule.step_proof
        )
        .expect("digest")
    );
    let mut missing = capsule.clone();
    missing.predecessor_lineage = KagemushaWalletLineageSlotV1::None;
    assert_invalid(missing.validate(), "lineage.slot");
    let with = |mutate: &dyn Fn(&mut KagemushaWalletLineageV1)| {
        let mut mutated = capsule.clone();
        if let KagemushaWalletLineageSlotV1::Present { lineage } = &mut mutated.predecessor_lineage
        {
            mutate(lineage);
        }
        mutated.validate()
    };
    assert_invalid(with(&|l| l.public.head = commitment(9)), "lineage.head");
    assert_invalid(
        with(&|l| l.public.wallet_id = [0x6d; 32]),
        "capsule.predecessor_lineage.wallet_id",
    );
    // Any change of the Ω bytes changes the bound proof digest and the output descriptor.
    assert_invalid(with(&|l| l.proof[0] ^= 1), "capsule.output.digest");
    // The successor core resynchronizes to Ω(pred)'s burned_total (§3.2).
    let mut stale = capsule.clone();
    stale.successor_state.core.burned_total = 7;
    assert_invalid(stale.validate(), "capsule.successor_state.burned_total");
}

#[test]
fn kagemusha_wallet_v1_completion_record_rebuilds_the_output() {
    // A non-Send transition releases its package.
    let f = android();
    let capsule = bootstrap_capsule(&f);
    let (receipt, package) = complete(&f, &f.credential, &capsule);
    let output = norito::encode_canonical(&package).expect("package frame");
    let record =
        KagemushaWalletCompletionRecordV1::new(&capsule, receipt, output.clone()).expect("record");
    assert_eq!(
        record.verify(&f.credential, &capsule).expect("verify"),
        package.verify(&f.credential).expect("package")
    );
    let frame = record.to_canonical_bytes().expect("frame");
    assert!(frame.len() <= KAGEMUSHA_WALLET_COMPLETION_RECORD_MAX_BYTES_V1);
    assert_eq!(
        record.completion_digest().expect("digest"),
        kagemusha_wallet_digest_v1(Role::Completion, &frame)
    );
    assert_eq!(
        KagemushaWalletCompletionRecordV1::decode_canonical(&frame, &f.credential.body.wallet_id)
            .expect("decode"),
        record
    );
    assert_invalid(
        KagemushaWalletCompletionRecordV1::decode_canonical(&frame, &[0x71; 32]),
        "completion.wallet_id",
    );

    // A Receive record binds the Payment digest its receipt signs.
    let receive = capsule_for(
        &f.credential,
        &transition_statement(
            &f,
            2,
            0,
            KagemushaWalletLifecycleV1::Active,
            KagemushaWalletEffectV1::Receive {
                credit_id: field_value(0x61),
                payer_wallet_id: [0x62; 32],
                amount: 9,
            },
        ),
        stand_in_proof(24),
        [0x76; 32],
    );
    let (receive_receipt, receive_package) = complete(&f, &f.credential, &receive);
    assert_eq!(receive_receipt.payment_digest, field_value(0x63));
    let receive_record = KagemushaWalletCompletionRecordV1::new(
        &receive,
        receive_receipt,
        norito::encode_canonical(&receive_package).expect("frame"),
    )
    .expect("receive record");
    receive_record
        .verify(&f.credential, &receive)
        .expect("receive record verifies");

    // A Send releases its canonical compact Payment carrying Ω(pred).
    let m = message_fixture();
    let request = m.request(true);
    let template = m.payment(true, 48);
    let send = capsule_with(
        &m.payer.credential,
        &template.send.statement,
        template.send.lineage.clone(),
        template.send.step_proof.clone(),
        [0; 32],
        [0x72; 32],
    );
    let (send_receipt, send_package) = complete(&m.payer, &m.payer.credential, &send);
    let payment = KagemushaWalletPaymentV1::assemble(&request, &m.payer.credential, send_package)
        .expect("payment");
    let payment_bytes = payment.to_canonical_bytes().expect("payment frame");
    let send_record =
        KagemushaWalletCompletionRecordV1::new(&send, send_receipt, payment_bytes.clone())
            .expect("send record");
    send_record
        .verify(&m.payer.credential, &send)
        .expect("send record verifies");
    // The Send output must be a valid Payment by this payer.
    assert!(
        KagemushaWalletCompletionRecordV1 {
            output: output.clone(),
            ..send_record.clone()
        }
        .verify(&m.payer.credential, &send)
        .is_err()
    );
    let mut other_payer = m.payer.credential;
    other_payer.body.issued_at_ms += 1;
    assert_invalid(
        send_record.verify(&other_payer, &send),
        "completion.credential",
    );
    // The released Payment must carry the capsule's Ω(pred).
    let mut other_lineage = send.clone();
    if let KagemushaWalletLineageSlotV1::Present { lineage } =
        &mut other_lineage.predecessor_lineage
    {
        lineage.proof.push(0);
    }
    assert!(
        send_record
            .verify(&m.payer.credential, &other_lineage)
            .is_err()
    );

    // Record and capsule bindings.
    let mut other_receipt = record.clone();
    other_receipt.receipt.capsule_digest = [0x73; 32];
    assert_invalid(
        other_receipt.validate(),
        "completion.receipt.capsule_digest",
    );
    let mut other_operation = record.clone();
    other_operation.receipt.operation_id = [0x74; 32];
    assert_invalid(
        other_operation.validate(),
        "completion.receipt.operation_id",
    );
    let mut empty = record.clone();
    empty.output.clear();
    assert_invalid(empty.validate(), "completion.output");
    let mut oversized = record.clone();
    oversized.output = vec![0; KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1 + 1];
    assert_invalid(oversized.validate(), "completion.output");
    let next = capsule_for(
        &f.credential,
        &transition_statement(&f, 1, 0, KagemushaWalletLifecycleV1::Active, send_effect()),
        stand_in_proof(16),
        capsule.capsule_digest().expect("digest"),
    );
    assert_invalid(
        record.verify(&f.credential, &next),
        "completion.capsule_digest",
    );
    // An output whose embedded receipt differs from the record's.
    let mut retargeted = package.clone();
    retargeted.receipt = send_receipt;
    let retargeted_record = KagemushaWalletCompletionRecordV1 {
        output: norito::encode_canonical(&retargeted).expect("frame"),
        ..record.clone()
    };
    assert_invalid(
        retargeted_record.verify(&f.credential, &capsule),
        "completion.receipt",
    );
    // An output of another statement under the same receipt.
    let mut other_statement = package.clone();
    other_statement.statement.successor = commitment(9);
    let other_statement_record = KagemushaWalletCompletionRecordV1 {
        output: norito::encode_canonical(&other_statement).expect("frame"),
        ..record.clone()
    };
    assert_invalid(
        other_statement_record.verify(&f.credential, &capsule),
        "completion.output",
    );
    // A capsule whose descriptor names another output.
    let mut redirected = capsule.clone();
    redirected.output.digest = [0x75; 32];
    assert!(record.verify(&f.credential, &redirected).is_err());
    let mut version = record;
    version.version = 2;
    assert!(matches!(
        version.validate(),
        Err(KagemushaWalletValidationErrorV1::UnsupportedVersion { .. })
    ));
}

#[test]
fn kagemusha_wallet_v1_fold_record_binds_one_lineage_per_head() {
    let f = android();
    let statement =
        transition_statement(&f, 6, 0, KagemushaWalletLifecycleV1::Active, send_effect());
    // Ω of the head selected by statement(h): stand-in Ω(pred) of the next statement.
    let next = transition_statement(&f, 7, 0, KagemushaWalletLifecycleV1::Active, send_effect());
    let lineage = lineage_for(&f.credential, &next);
    assert_eq!(lineage.public.head, statement.successor);
    let record = KagemushaWalletFoldRecordV1 {
        version: KAGEMUSHA_WALLET_VERSION_V1,
        scheme_id: f.credential.body.scheme_id,
        wallet_id: f.credential.body.wallet_id,
        first_sequence: 4,
        sequence: 7,
        head: statement.successor,
        capsule_digest: [0x77; 32],
        lineage: lineage.clone(),
    };
    record.validate().expect("fold record");
    assert_eq!(record.lineage_digest(), lineage.lineage_digest());
    let frame = record.to_canonical_bytes().expect("frame");
    assert!(frame.len() <= KAGEMUSHA_WALLET_FOLD_RECORD_MAX_BYTES_V1);
    assert_eq!(
        record.fold_digest().expect("digest"),
        kagemusha_wallet_digest_v1(Role::Fold, &frame)
    );
    assert_eq!(
        KagemushaWalletFoldRecordV1::decode_canonical(&frame, &f.credential.body.scheme_id)
            .expect("decode"),
        record
    );
    assert!(matches!(
        KagemushaWalletFoldRecordV1::decode_canonical(&frame, &[0x78; 32]),
        Err(KagemushaWalletValidationErrorV1::SchemeMismatch {
            field: "fold.scheme_id"
        })
    ));
    let reject = |mutate: &dyn Fn(&mut KagemushaWalletFoldRecordV1), field: &str| {
        let mut record = record.clone();
        mutate(&mut record);
        assert_invalid(record.validate(), field);
    };
    reject(&|r| r.head = commitment(9), "fold.lineage.head");
    reject(
        &|r| r.head = KagemushaWalletStateCommitmentV1::ZERO,
        "fold.head",
    );
    reject(&|r| r.wallet_id = [0x79; 32], "fold.lineage.wallet_id");
    reject(&|r| r.first_sequence = 8, "fold.first_sequence");
    reject(&|r| r.capsule_digest = [0; 32], "fold.capsule_digest");
    reject(&|r| r.lineage.proof.clear(), "lineage.proof");
    let mut other_scheme = record.clone();
    other_scheme.scheme_id = [0x7a; 32];
    assert!(matches!(
        other_scheme.validate(),
        Err(KagemushaWalletValidationErrorV1::SchemeMismatch {
            field: "fold.lineage.scheme_id"
        })
    ));
    let mut version = record.clone();
    version.lineage.public.version = 2;
    assert!(matches!(
        KagemushaWalletFoldRecordV1::decode_canonical(
            &norito::encode_canonical(&version).expect("encode"),
            &f.credential.body.scheme_id
        ),
        Err(KagemushaWalletValidationErrorV1::UnsupportedVersion {
            field: "lineage.version",
            ..
        })
    ));
    let mut oversized = record;
    oversized.lineage.proof = vec![0x5a; KAGEMUSHA_WALLET_FOLD_RECORD_MAX_BYTES_V1];
    assert!(matches!(
        oversized.to_canonical_bytes(),
        Err(KagemushaWalletValidationErrorV1::EncodedSizeExceeded { .. })
    ));
}
