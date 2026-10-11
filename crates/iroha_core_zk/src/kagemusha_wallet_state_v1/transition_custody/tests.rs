//! Selected snapshot and preparation-draft regressions with explicit mock proof authority.

use super::*;
use crate::kagemusha_wallet_state_v1::{
    preparation_custody::SourceCustodyV1, transition_custody::PreparedTransitionV1,
};

#[test]
fn bootstrap_snapshot_loss_refuses_folding_before_new_proof_work() {
    let mut wallet = wallet();
    wallet.commit(bootstrap()).unwrap();
    wallet.scheduler().set_activity(true, false);
    let (_, manifest) = wallet.manifest().unwrap();
    let address: [u8; 32] = manifest
        .capsule_sources
        .get(&mut wallet.archive, &manifest.capsule)
        .unwrap()
        .unwrap()
        .try_into()
        .unwrap();
    let bytes = wallet.archive.read_object(&address, 32 * 1024).unwrap();
    wallet.archive.remove(ArchiveKey::Object(address)).unwrap();
    assert!(matches!(wallet.fold_once(), Err(Error::WitnessLost(_))));
    assert_eq!(wallet.proofs.folds.load(Ordering::SeqCst), 0);
    // An unrelated durable snapshot is not a substitute for the selected original.
    wallet.archive.write_object(&[1, 2, 3], 32 * 1024).unwrap();
    assert!(matches!(wallet.fold_once(), Err(Error::WitnessLost(_))));
    wallet
        .archive
        .put(ArchiveKey::Object(address), &bytes)
        .unwrap();
    assert!(matches!(
        wallet.fold_once().unwrap(),
        FoldStatus::Checkpoint {
            sequence: 0,
            ordinal: 0
        }
    ));
    assert_eq!(wallet.fold_once().unwrap(), FoldStatus::Folded(0));
}

#[test]
fn an_unselected_snapshot_never_changes_current_source_custody() {
    let mut wallet = wallet();
    wallet.commit(bootstrap()).unwrap();
    let (root, manifest) = wallet.manifest().unwrap();
    let selected = wallet.indexed_step(&manifest, 0).unwrap();
    let source = wallet.source_custody(&manifest, &selected).unwrap();
    wallet.retain_source_custody([0x87; 32], &source).unwrap();
    let (after, selected_manifest) = wallet.manifest().unwrap();
    assert_eq!(after, root);
    assert!(
        selected_manifest
            .capsule_sources
            .get(&mut wallet.archive, &[0x87; 32])
            .unwrap()
            .is_none()
    );
    assert_eq!(
        archive::encode(
            &wallet
                .source_custody(&selected_manifest, &selected)
                .unwrap()
        )
        .unwrap(),
        archive::encode(&source).unwrap()
    );
    assert_eq!(wallet.custody.signatures, 1);
}

#[test]
fn preparation_draft_must_equal_the_rederived_draft_and_actual_successor() {
    let mut wallet = wallet();
    wallet.commit(bootstrap()).unwrap();
    let (_, manifest) = wallet.manifest().unwrap();
    let selected = wallet.indexed_step(&manifest, 0).unwrap();
    let source = wallet.source_custody(&manifest, &selected).unwrap();
    let mut after = selected.frozen.capsule.successor_state;
    let mut wrong = source.clone();
    let mut tree = map_tree::PersistentMapV1::default();
    tree.insert(&mut wallet.archive, field(17), field(18))
        .unwrap();
    wrong.maps.replace_pending(tree);
    let plan = |draft: SourceCustodyV1| PreparedTransitionV1 {
        request: NativeIntentV1::user(OperationRequestV1 {
            request_id: [41; 32],
            action: OperationActionV1::Retire,
        }),
        native: vec![1],
        source: manifest.capsule,
        draft,
    };
    fn view<'a>(
        store: &'a mut MemoryArchive,
        source: &SourceCustodyV1,
        state: &KagemushaWalletStateV1,
        manifest: &manifest::Manifest,
    ) -> PreparationCustodyV1<'a> {
        PreparationCustodyV1::new(
            store,
            source,
            state,
            KagemushaWalletOperationKindV1::Retiring,
            None,
            manifest.issued_requests,
            manifest.direct_anchors,
            manifest.finality_epochs,
        )
        .unwrap()
    }

    let custody = TransitionCustodyV1::new(
        Some(plan(wrong)),
        Some(view(
            &mut wallet.archive,
            &source,
            &selected.frozen.capsule.successor_state,
            &manifest,
        )),
    )
    .unwrap();
    assert!(matches!(custody.finish(&after), Err(Error::WitnessLost(_))));
    let custody = TransitionCustodyV1::new(
        Some(plan(source.clone())),
        Some(view(
            &mut wallet.archive,
            &source,
            &selected.frozen.capsule.successor_state,
            &manifest,
        )),
    )
    .unwrap();
    after.core.pending_outgoing_root = field(99);
    assert!(matches!(custody.finish(&after), Err(Error::WitnessLost(_))));
    let custody = TransitionCustodyV1::new(
        Some(plan(source.clone())),
        Some(view(
            &mut wallet.archive,
            &source,
            &selected.frozen.capsule.successor_state,
            &manifest,
        )),
    )
    .unwrap();
    assert_eq!(
        archive::encode(
            &custody
                .finish(&selected.frozen.capsule.successor_state)
                .unwrap()
                .unwrap()
        )
        .unwrap(),
        archive::encode(&source).unwrap()
    );
    assert!(TransitionCustodyV1::new(Some(plan(source)), None).is_err());
}

fn setup_quote(source: &FrozenTransition) -> (KagemushaWalletOfferV1, KagemushaWalletRequestV1) {
    let template: KagemushaWalletRecoveryCapsuleV1 = fixture("KagemushaWalletRecoveryCapsuleV1");
    let original = template
        .retained_inputs
        .iter()
        .find(|input| input.role == KagemushaWalletRetainedInputRoleV1::Request)
        .unwrap();
    let mut request: KagemushaWalletRequestV1 = archive::decode(&original.bytes).unwrap();
    let remote = request.receiver_credential;
    let issuer = *request
        .certificates
        .certificate(
            &remote.body.issuer_certificate,
            KagemushaWalletSignerRoleV1::Enrollment,
        )
        .unwrap();
    let body = KagemushaWalletOfferBodyV1 {
        version: 1,
        scheme_id: remote.body.scheme_id,
        asset_digest: remote.body.asset_digest,
        payer_wallet_id: remote.body.wallet_id,
        payer_credential_digest: remote.credential_digest(),
        next_send: 0,
        amount: 7,
        session_nonce: [72; 32],
    };
    fn sign(
        credential: &KagemushaWalletCredentialV1,
        message: &[u8],
    ) -> KagemushaDeviceSignatureV1 {
        let signature: Signature = signer(credential).sign(message);
        KagemushaDeviceSignatureV1::from_raw_bytes(
            &signature.normalize_s().unwrap_or(signature).to_bytes(),
        )
        .unwrap()
    }
    let offer = KagemushaWalletOfferV1 {
        body,
        payer_credential: remote,
        certificates: KagemushaWalletCertificateSetV1::new(vec![issuer]).unwrap(),
        signature: sign(&remote, &body.signing_message()),
    };
    let scheme: KagemushaWalletSchemeV1 = fixture("KagemushaWalletSchemeV1");
    offer.verify(&scheme).unwrap();
    let local = source.credential;
    let state = &source.capsule.successor_state;
    let issuer = enrollment_issuer(&local);
    request.receiver_credential = local;
    request.certificates = KagemushaWalletCertificateSetV1::new(vec![issuer]).unwrap();
    request.fee_schedule = KagemushaWalletFeeScheduleSlotV1::None;
    request.body = KagemushaWalletRequestBodyV1 {
        version: 1,
        scheme_id: local.body.scheme_id,
        asset_digest: local.body.asset_digest,
        payer_wallet_id: remote.body.wallet_id,
        payer_account_digest: remote.body.account_digest,
        receiver_wallet_id: local.body.wallet_id,
        receiver_account_digest: local.body.account_digest,
        send_ordinal: offer.body.next_send,
        receiver_credential_digest: local.credential_digest(),
        amount: offer.body.amount,
        fee_schedule: [0; 32],
        fee: 0,
        policy_epoch: state.core.policy_epoch,
        scheme_policy: state.rest.scheme_policy,
        receiver_accepted_time_ms: state.core.accepted_time_floor_ms,
        receiver_blacklist_version: 0,
        receiver_blacklist_root: [0; 32],
        certificates: request.certificates.digest().unwrap(),
        nonce: [73; 32],
    };
    request.signature = sign(&local, &request.body.signing_message());
    request.verify(&scheme).unwrap();
    (offer, request)
}

fn begin_setup_request(
    wallet: &mut Coordinator<TestCustody, MemoryArchive, TestProofs>,
    source: &FrozenTransition,
) -> (
    native_owner::sessions::Action,
    native_owner::sessions::Plan,
    KagemushaWalletRequestV1,
) {
    let (offer, mut request) = setup_quote(source);
    let action = native_owner::sessions::Action::Request {
        offer: archive::encode(&offer).unwrap(),
        fee: None,
    };
    let plan = wallet.setup([74; 32], &action).unwrap();
    request.body.nonce = plan.nonce;
    let signature: Signature = signer(&source.credential).sign(&request.body.signing_message());
    request.signature = KagemushaDeviceSignatureV1::from_raw_bytes(
        &signature.normalize_s().unwrap_or(signature).to_bytes(),
    )
    .unwrap();
    request.validate().unwrap();
    (action, plan, request)
}

#[test]
fn request_and_setup_output_publish_together_and_replay_exactly_after_a_new_head() {
    for selected_before_error in [false, true] {
        let mut wallet = wallet();
        let boot = bootstrap();
        wallet.commit(boot.clone()).unwrap();
        let (action, mut plan, request) = begin_setup_request(&mut wallet, &boot);
        let original = archive::encode(&request).unwrap();
        let signatures = wallet.custody.signatures;
        wallet.custody.fail_publication = Some(selected_before_error);
        assert!(
            wallet
                .finish_setup(
                    [74; 32],
                    &action,
                    &mut plan,
                    &original,
                    Some((&request, None))
                )
                .is_err()
        );
        let (_, manifest) = wallet.manifest().unwrap();
        assert_eq!(
            manifest
                .issued_requests
                .get(&mut wallet.archive, &request.request_digest())
                .unwrap()
                .is_some(),
            selected_before_error
        );
        // The exact production helper can never select a signed output without the
        // associated historical Request decision in the same manifest generation.
        let recovered = wallet.setup([74; 32], &action).unwrap();
        assert_eq!(recovered.output.is_some(), selected_before_error);
        assert_eq!(recovered.nonce, plan.nonce);
        let mut wallet = Coordinator::new(
            wallet.custody,
            wallet.archive,
            wallet.proofs,
            wallet.scheme_id,
            wallet.wallet_id,
        )
        .unwrap();
        let mut plan = wallet.setup([74; 32], &action).unwrap();
        if plan.output.is_none() {
            wallet
                .finish_setup(
                    [74; 32],
                    &action,
                    &mut plan,
                    &original,
                    Some((&request, None)),
                )
                .unwrap();
        }
        assert_eq!(wallet.issued_setup_request(&request).unwrap(), original);
        assert_eq!(wallet.custody.signatures, signatures);
        let load = frozen(
            Some(&boot),
            KagemushaWalletEffectV1::Load {
                receipt_digest: field(90),
                load_ordinal: 0,
                amount: 1,
                online_charge: 0,
            },
        );
        wallet.commit(load).unwrap();
        let replay = wallet.setup([74; 32], &action).unwrap();
        assert_eq!(replay.source, plan.source);
        assert_eq!(replay.nonce, plan.nonce);
        assert_eq!(replay.output, plan.output);
        assert_eq!(wallet.issued_setup_request(&request).unwrap(), original);
        // A missing selected original cannot be reconstructed from transport input.
        let (_, manifest) = wallet.manifest().unwrap();
        let record: preparation_custody::IssuedRequestCustodyV1 = archive::decode(
            &manifest
                .issued_requests
                .get(&mut wallet.archive, &request.request_digest())
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        wallet
            .archive
            .remove(ArchiveKey::Object(record.request))
            .unwrap();
        assert!(matches!(
            wallet.issued_setup_request(&request),
            Err(Error::WitnessLost(_))
        ));
    }
}

#[test]
fn a_new_setup_request_cannot_be_published_from_a_different_selected_head() {
    let mut wallet = wallet();
    let boot = bootstrap();
    wallet.commit(boot.clone()).unwrap();
    let (action, mut plan, request) = begin_setup_request(&mut wallet, &boot);
    let load = frozen(
        Some(&boot),
        KagemushaWalletEffectV1::Load {
            receipt_digest: field(90),
            load_ordinal: 0,
            amount: 1,
            online_charge: 0,
        },
    );
    wallet.commit(load).unwrap();
    let (root, _) = wallet.manifest().unwrap();
    assert!(matches!(
        wallet.finish_setup(
            [74; 32],
            &action,
            &mut plan,
            &archive::encode(&request).unwrap(),
            Some((&request, None))
        ),
        Err(Error::Invalid(_))
    ));
    assert_eq!(wallet.manifest().unwrap().0, root);
    assert_eq!(wallet.custody.signatures, 2);
    assert!(wallet.setup([74; 32], &action).unwrap().output.is_none());
    assert!(matches!(
        wallet.issued_setup_request(&request),
        Err(Error::WitnessLost(_))
    ));
}

#[test]
fn retiring_preserves_outgoing_offers_and_exact_requests_but_refuses_new_quotes() {
    let mut wallet = wallet();
    let boot = bootstrap();
    wallet.commit(boot.clone()).unwrap();
    snapshot_test_fold(&mut wallet);
    let (request_action, mut request_plan, request) = begin_setup_request(&mut wallet, &boot);
    let original = archive::encode(&request).unwrap();
    wallet
        .finish_setup(
            [74; 32],
            &request_action,
            &mut request_plan,
            &original,
            Some((&request, None)),
        )
        .unwrap();
    let (_, manifest) = wallet.manifest().unwrap();
    let predecessor = wallet.indexed_step(&manifest, 0).unwrap();
    let source = wallet.source_custody(&manifest, &predecessor).unwrap();
    let fold = wallet.read_fold(&predecessor).unwrap().unwrap();
    let mut retiring = frozen(Some(&boot), KagemushaWalletEffectV1::Retiring);
    let c = &mut retiring.capsule;
    c.predecessor_lineage = KagemushaWalletLineageSlotV1::Present {
        lineage: fold.record.lineage.clone(),
    };
    c.statement.lineage_burned_total = fold.record.lineage.public.burned_total;
    c.statement.lineage_pending_outgoing_root = fold.record.lineage.public.pending_outgoing_root;
    c.successor_state.core.burned_total = c.statement.lineage_burned_total;
    rebind_frozen_successor(&mut retiring);
    retiring.validate().unwrap();
    // The explicit mock relation preserves every map/original. Retain that exact snapshot
    // so this test exercises the production setup guard under a selected Retiring source.
    source
        .require(&mut wallet.archive, &retiring.capsule.successor_state)
        .unwrap();
    wallet
        .retain_source_custody(retiring.capsule.capsule_digest().unwrap(), &source)
        .unwrap();
    wallet.commit(retiring).unwrap();
    let (_, manifest) = wallet.manifest().unwrap();
    let retiring_head = manifest.capsule;
    let offer = wallet
        .setup(
            [75; 32],
            &native_owner::sessions::Action::Offer { amount: 7 },
        )
        .unwrap();
    assert_eq!(offer.source, retiring_head);
    assert!(offer.output.is_none());
    assert_eq!(
        wallet.setup([74; 32], &request_action).unwrap().output,
        request_plan.output
    );
    assert_eq!(wallet.issued_setup_request(&request).unwrap(), original);
    let (before, _) = wallet.manifest().unwrap();
    assert!(matches!(
        wallet.setup([76; 32], &request_action),
        Err(Error::Invalid("new Request requires active wallet"))
    ));
    assert_eq!(wallet.manifest().unwrap().0, before);
}
