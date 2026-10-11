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
    let state = KagemushaWalletStateV1::bootstrap(&credential, field(7)).unwrap();
    let mut capsule: KagemushaWalletRecoveryCapsuleV1 = fixture("KagemushaWalletRecoveryCapsuleV1");
    capsule.kind = effect.kind();
    capsule.statement.effect = effect;
    capsule.successor_state = state;
    capsule.payment_digest = field(88);
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
    archive.frozen.capsule.kind = KagemushaWalletOperationKindV1::ArchiveSent;
    archive.frozen.capsule.statement.effect = KagemushaWalletEffectV1::ArchiveSent {
        credit_id: field(3),
        credited: field(12),
    };
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
    assert!(view.blacklist_history().is_err());
    assert!(view.finish(&public(field(90), field(91))).is_err());
}
