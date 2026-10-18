//! Fixed map witness access tests; synthetic completions here grant no proof authority.

use super::super::tests::{MemoryArchive, enrollment_issuer, fixture};
use super::*;

fn field(value: u128) -> [u8; 32] {
    kagemusha_wallet_field_from_u128_v1(value)
}

fn setup(effect: KagemushaWalletEffectV1) -> (MemoryArchive, ReleasedStep, SourceCustodyV1) {
    let credential: KagemushaWalletCredentialV1 = fixture("KagemushaWalletCredentialV1");
    let certificate = enrollment_issuer(&credential);
    let certificates = KagemushaWalletCertificateSetV1::new(vec![certificate]).unwrap();
    let boot = super::super::tests::bootstrap();
    let mut frozen = super::super::tests::frozen(Some(&boot), effect);
    let mut body = frozen.capsule.body().clone();
    if body.kind == KagemushaWalletOperationKindV1::Receive {
        body.payment_digest = field(88);
        body.output = KagemushaWalletOutputDescriptorV1::for_transition(
            &body.statement,
            &body.proof_digest().unwrap(),
            &body.payment_digest,
        )
        .unwrap();
    }
    let state = body.successor_state;
    frozen.capsule = super::super::tests::seal_body(body);
    let capsule = frozen.capsule;
    let record: KagemushaWalletCompletionRecordV1 = fixture("KagemushaWalletCompletionRecordV1");
    let released = ReleasedStep {
        frozen: FrozenTransition {
            credential: credential.clone(),
            capsule,
        },
        retained: Retained {
            operation_id: [1; 32],
            capsule_digest: [2; 32],
            selected_generation: 1,
            completion_digest: [3; 32],
            frame: record.to_canonical_bytes().unwrap(),
            record,
        },
    };
    let mut store = MemoryArchive::new();
    let source = SourceCustodyV1::bootstrap(
        &mut store,
        &state,
        &credential.to_canonical_bytes().unwrap(),
        &archive::encode(&certificates).unwrap(),
    )
    .unwrap();
    (store, released, source)
}

fn sources(before: Option<SourceCustodyV1>, after: SourceCustodyV1) -> FoldSourcesV1 {
    FoldSourcesV1 {
        before,
        after,
        preparation: None,
        issued: IndexRoot::default(),
        anchors: IndexRoot::default(),
        epochs: IndexRoot::default(),
    }
}

fn public(credit: [u8; 32], pending: [u8; 32]) -> KagemushaWalletLineagePublicV1 {
    let fold: KagemushaWalletFoldRecordV1 = fixture("KagemushaWalletFoldRecordV1");
    KagemushaWalletLineagePublicV1 {
        credit_digest_root: credit,
        pending_outgoing_root: pending,
        ..fold.lineage.public
    }
}

#[test]
fn receive_witness_is_idempotent_and_preserves_first_payment_and_burn() {
    let effect = KagemushaWalletEffectV1::Receive {
        credit_id: field(3),
        payer_wallet_id: [4; 32],
        amount: 9,
    };
    let (mut store, step, source) = setup(effect);
    let mut view = FoldCustodyV1::new(
        &mut store,
        None,
        &step,
        sources(None, source.clone()),
        credit_tree::CreditTree::default(),
        map_tree::PersistentMapV1::default(),
    )
    .unwrap();
    let empty = view.credit_root();
    let witness = view.credit_record(true).unwrap();
    let root = view.credit_root();
    assert_eq!(
        witness
            .verify(
                &empty,
                &KagemushaWalletCreditDigestLeafV1 {
                    credit_id: field(3),
                    payment_digest: field(88),
                    burned: true
                }
            )
            .unwrap(),
        root
    );
    assert_eq!(view.credit_record(true).unwrap(), witness);
    assert!(view.credit_record(false).is_err());
    assert!(view.pending_insert().is_err());
    let expected = public(root, view.pending_root());
    let (credits, pending) = view.finish(&expected).unwrap();
    let mut replay = FoldCustodyV1::new(
        &mut store,
        None,
        &step,
        sources(None, source),
        credits,
        pending,
    )
    .unwrap();
    assert!(matches!(
        replay.credit_record(false).unwrap(),
        KagemushaWalletCreditDigestRecordV1::Present { .. }
    ));
    assert_eq!(replay.credit_root(), root);
    replay.finish(&expected).unwrap();
}

#[test]
fn send_pending_uses_the_selected_statement_and_archive_keeps_both_branches() {
    let effect = KagemushaWalletEffectV1::Send {
        credit_id: field(3),
        receiver_wallet_id: [4; 32],
        send_ordinal: 2,
        amount: 9,
        fee: 1,
        request: field(8),
        accepted_lower_ms: 0,
        accepted_upper_ms: 0,
    };
    let (mut store, step, source) = setup(effect);
    let mut send = FoldCustodyV1::new(
        &mut store,
        None,
        &step,
        sources(None, source.clone()),
        credit_tree::CreditTree::default(),
        map_tree::PersistentMapV1::default(),
    )
    .unwrap();
    let empty = send.pending_root();
    let witness = send.pending_insert().unwrap();
    assert_eq!(send.pending_insert().unwrap(), witness);
    assert_ne!(send.pending_root(), empty);
    assert!(send.credit_record(false).is_err());
    assert!(send.pending_remove().is_err());
    let expected = public(send.credit_root(), send.pending_root());
    let (credits, pending) = send.finish(&expected).unwrap();
    let mut archive = step.clone();
    let mut body = archive.frozen.capsule.body().clone();
    body.kind = KagemushaWalletOperationKindV1::ArchiveSent;
    body.statement.effect = KagemushaWalletEffectV1::ArchiveSent {
        credit_id: field(3),
        credited: field(12),
    };
    body.predecessor_lineage = KagemushaWalletLineageSlotV1::None;
    body.statement.lineage_burned_total = 0;
    body.statement.lineage_pending_outgoing_root = [0; 32];
    body.retained_inputs = [
        KagemushaWalletRetainedInputRoleV1::Request,
        KagemushaWalletRetainedInputRoleV1::Payment,
        KagemushaWalletRetainedInputRoleV1::Credited,
        KagemushaWalletRetainedInputRoleV1::Credential,
        KagemushaWalletRetainedInputRoleV1::CertificateSet,
    ]
    .into_iter()
    .map(|role| KagemushaWalletRetainedInputV1 {
        role,
        bytes: vec![1],
    })
    .collect();
    body.operation_id = body.statement.operation_id(&body.wallet_id).unwrap();
    body.output = KagemushaWalletOutputDescriptorV1::for_transition(
        &body.statement,
        &body.proof_digest().unwrap(),
        &body.payment_digest,
    )
    .unwrap();
    archive.frozen.capsule = super::super::tests::seal_body(body);
    for remove in [false, true] {
        let mut view = FoldCustodyV1::new(
            &mut store,
            None,
            &archive,
            sources(None, source.clone()),
            credits.clone(),
            pending.clone(),
        )
        .unwrap();
        let removal = view.pending_remove().unwrap();
        assert_eq!(view.pending_remove().unwrap(), removal);
        assert_eq!(view.pending_root(), pending.root());
        let removed = removal.verify(&pending.root(), &field(3)).unwrap();
        assert_eq!(removed, empty);
        let desired = public(
            view.credit_root(),
            if remove { removed } else { pending.root() },
        );
        let (_, selected) = view.finish(&desired).unwrap();
        assert_eq!(selected.root(), desired.pending_outgoing_root);
    }
}

#[test]
fn historical_originals_are_exact_and_unknown_final_roots_reject() {
    let effect = KagemushaWalletEffectV1::Retiring;
    let (mut store, step, source) = setup(effect);
    let mut view = FoldCustodyV1::new(
        &mut store,
        Some(&step),
        &step,
        sources(Some(source.clone()), source),
        credit_tree::CreditTree::default(),
        map_tree::PersistentMapV1::default(),
    )
    .unwrap();
    assert_eq!(
        view.predecessor().unwrap().retained.frame,
        step.retained.frame
    );
    for role in [
        PreparationOriginalV1::CurrentCredential,
        PreparationOriginalV1::EnrollmentCertificates,
    ] {
        assert_eq!(
            view.predecessor_original(role).unwrap(),
            view.successor_original(role).unwrap()
        );
    }
    assert!(view.finish(&public(field(90), field(91))).is_err());
}

/// A fold replays a committed step: its derivation custody never holds the wallet's local
/// blacklist, so a list installed after the operation cannot refuse its fold.
#[test]
fn fold_preparation_replays_without_the_local_blacklist() {
    let (mut store, step, source) = setup(KagemushaWalletEffectV1::Retiring);
    let plan = transition_custody::PreparedTransitionV1 {
        request: NativeIntentV1::user(OperationRequestV1 {
            request_id: [41; 32],
            action: OperationActionV1::Retire,
        }),
        native: std::sync::Arc::new(PrivateArchiveBytes::copy_from(&[1]).unwrap()),
        source: step.frozen.capsule.custody_digest(),
        draft: source.clone(),
    };
    let mut view = FoldCustodyV1::new(
        &mut store,
        Some(&step),
        &step,
        FoldSourcesV1 {
            before: Some(source.clone()),
            after: source,
            preparation: Some(plan),
            issued: IndexRoot::default(),
            anchors: IndexRoot::default(),
            epochs: IndexRoot::default(),
        },
        credit_tree::CreditTree::default(),
        map_tree::PersistentMapV1::default(),
    )
    .unwrap();
    let (request, _, _, mut custody) = view.preparation().unwrap();
    assert_eq!(request.kind(), KagemushaWalletOperationKindV1::Retiring);
    assert!(custody.local_blacklist().unwrap().is_none());
}

/// D6b key inputs (deploy-pipeline §7.4 test 11, reviews G2 and K3): the source identities
/// follow the predecessor and successor source records and every part of the retained
/// preparation, and ignore the issued-Request, direct-anchor and finality-epoch roots, which
/// are insert-once indexes. They read no store.
#[test]
fn source_digests_follow_records_and_preparation_but_no_index_root() {
    let (mut store, step, source) = setup(KagemushaWalletEffectV1::Retiring);
    let mut draft = source.clone();
    let mut tree = map_tree::PersistentMapV1::default();
    tree.insert(&mut store, field(17), field(18)).unwrap();
    draft.maps.replace_pending(tree);
    let plan = |native: u8, request: u8, capsule: u8, draft: &SourceCustodyV1| {
        transition_custody::PreparedTransitionV1 {
            request: NativeIntentV1::user(OperationRequestV1 {
                request_id: [request; 32],
                action: OperationActionV1::Retire,
            }),
            native: std::sync::Arc::new(PrivateArchiveBytes::copy_from(&[native]).unwrap()),
            source: [capsule; 32],
            draft: draft.clone(),
        }
    };
    let mut digests =
        |before: bool, preparation: Option<transition_custody::PreparedTransitionV1>, index: u8| {
            let fold_sources = FoldSourcesV1 {
                before: before.then(|| source.clone()),
                after: source.clone(),
                preparation,
                issued: IndexRoot([index; 32]),
                anchors: IndexRoot([index ^ 1; 32]),
                epochs: IndexRoot([index ^ 2; 32]),
            };
            FoldCustodyV1::new(
                &mut store,
                before.then_some(&step),
                &step,
                fold_sources,
                credit_tree::CreditTree::default(),
                map_tree::PersistentMapV1::default(),
            )
            .unwrap()
            .source_digests()
            .unwrap()
        };
    let cold = digests(false, None, 0);
    assert_eq!((cold[0], cold[2]), ([0; 32], [0; 32]), "absent sources");
    assert_eq!(
        cold[1],
        canonical_digest(b"KAGEMUSHA fold source after v1", &source).unwrap()
    );
    assert_eq!(
        digests(false, None, 9),
        cold,
        "index roots are not key inputs"
    );
    let folded = digests(true, None, 0);
    assert_ne!(folded[0], [0; 32]);
    assert_eq!(folded[1], cold[1]);
    let prepared = digests(true, Some(plan(1, 41, 42, &source)), 0);
    assert_ne!(prepared[2], [0; 32]);
    assert_eq!(
        digests(true, Some(plan(1, 41, 42, &source)), 7),
        prepared,
        "index roots are not key inputs"
    );
    for changed in [
        plan(2, 41, 42, &source),
        plan(1, 43, 42, &source),
        plan(1, 41, 44, &source),
        plan(1, 41, 42, &draft),
    ] {
        assert_ne!(digests(true, Some(changed), 0)[2], prepared[2]);
    }
    assert_ne!(
        canonical_digest(b"KAGEMUSHA fold source after v1", &draft).unwrap(),
        cold[1],
        "a changed source record changes its identity"
    );
}
