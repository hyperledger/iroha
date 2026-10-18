use iroha_data_model::isi::consensus_keys::{
    ApplyThresholdKeyLifecycleCertificateV1, ThresholdKeyLifecycleActionV1,
    ThresholdKeyLifecycleCertificateV1, ThresholdKeyLifecycleSignatureV1,
};

fn lifecycle_ordinary_fixture(
    has_parent: bool,
) -> (
    SharedAppState,
    KeyPair,
    Vec<KeyPair>,
    ThresholdKeyLifecycleCertificateV1,
) {
    let (mut app, _, validators) = app_with_finalized_block_for_test(has_parent);
    let authority_key = checked_torii_test_ed25519_keypair(0x39, "lifecycle ingress authority");
    let roster = validators
        .iter()
        .map(|key| PeerId::new(key.public_key().clone()))
        .collect::<Vec<_>>();
    let unique = Arc::get_mut(&mut app).unwrap();
    unique.local_peer_id = Some(roster[0].clone());
    unique.torii_proxy_bridge_signer = validators[0].clone();
    let mut certificate = ThresholdKeyLifecycleCertificateV1 {
        version: iroha_core::state::THRESHOLD_KEY_LIFECYCLE_CERTIFICATE_VERSION_V1,
        action: ThresholdKeyLifecycleActionV1::FinalizeGlobalBeaconKey,
        expected_active_session_id: None,
        effective_height: app.state.committed_height() as u64 + 1,
        network_id: *app.state.network_id_ref(),
        roster_hash: iroha_core::beacon::global_threshold_beacon_roster_hash_v1(&roster),
        committee_size: 4,
        quorum: 3,
        session_id: [0x41; 32],
        transcript_hash: [0x42; 32],
        public_state: vec![0x43; 16],
        signatures: Vec::new(),
    };
    lifecycle_sign_certificate(&mut certificate, &validators);
    (app, authority_key, validators, certificate)
}

fn lifecycle_sign_certificate(
    certificate: &mut ThresholdKeyLifecycleCertificateV1,
    keys: &[KeyPair],
) {
    let preimage = iroha_core::state::threshold_key_lifecycle_certificate_preimage_v1(certificate)
        .expect("native lifecycle signing preimage");
    certificate.signatures = keys
        .iter()
        .take(3)
        .enumerate()
        .map(|(index, key)| ThresholdKeyLifecycleSignatureV1 {
            signer_index: u16::try_from(index).expect("small fixture index"),
            signature: Signature::try_new(key.private_key(), &preimage)
                .expect("sign exact lifecycle QC"),
        })
        .collect();
}

fn lifecycle_ordinary_transaction(
    app: &SharedAppState,
    key: &KeyPair,
    instructions: Vec<iroha_data_model::isi::InstructionBox>,
) -> SignedTransaction {
    TransactionBuilder::new(
        *app.state.network_id_ref(),
        AccountId::new(key.public_key().clone()),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions(instructions)
    .sign(key.private_key())
}

async fn lifecycle_submit(app: &SharedAppState, transaction: SignedTransaction) -> Response {
    super::submit_signed_transaction_for_ingress(
        app.clone(),
        HeaderMap::new(),
        Some(crate::utils::extractors::ExtractAccept(
            axum::http::HeaderValue::from_static(crate::utils::NORITO_MIME_TYPE),
        )),
        transaction,
    )
    .await
    .unwrap_or_else(IntoResponse::into_response)
}

#[tokio::test]
async fn lifecycle_ordinary_ingress_accepts_exact_quorum_and_preserves_wire_identity() {
    let (app, key, _, certificate) = lifecycle_ordinary_fixture(true);
    let transaction = lifecycle_ordinary_transaction(
        &app,
        &key,
        vec![ApplyThresholdKeyLifecycleCertificateV1 { certificate }.into()],
    );
    let submitted_hash = transaction.hash();
    let entrypoint_hash = transaction.hash_as_entrypoint();
    let submitted_wire =
        <SignedTransaction as iroha_version::codec::EncodeVersioned>::encode_versioned(
            &transaction,
        );
    let response = lifecycle_submit(&app, transaction).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-signed-transaction-hash")
            .unwrap(),
        submitted_hash.to_string().as_str()
    );
    assert_eq!(
        response.headers().get("x-iroha-entrypoint-hash").unwrap(),
        entrypoint_hash.to_string().as_str()
    );
    let body = torii_body_bytes(response, "ordinary lifecycle receipt").await;
    let receipt: TransactionSubmissionReceipt =
        norito::decode_from_bytes(&body).expect("signed local submission receipt");
    receipt.verify().expect("signed ordinary receipt");
    assert_eq!(receipt.payload.entrypoint_hash, entrypoint_hash);
    assert_eq!(
        receipt.payload.signed_transaction_hash,
        Some(submitted_hash)
    );
    assert_eq!(app.queue.active_len(), 1);
    let state = app.state.view();
    let queued = app.queue.all_transactions(&state).collect::<Vec<_>>();
    assert_eq!(queued.len(), 1);
    let stored = queued[0]
        .external()
        .expect("exact external lifecycle transaction");
    assert_eq!(
        <SignedTransaction as iroha_version::codec::EncodeVersioned>::encode_versioned(stored),
        submitted_wire
    );
    assert_eq!(receipt.payload.submitted_at_height, 2);
    assert!(!app.state.has_committed_entrypoint(entrypoint_hash));
    assert_eq!(lifecycle_pending_wire(&app).len(), 1);
}

#[tokio::test]
async fn ordinary_single_route_application_retains_local_custody_and_rejects_mixed_lifecycle() {
    let (app, key, _, certificate) = lifecycle_ordinary_fixture(true);
    let before = lifecycle_pending_wire(&app);
    let response = lifecycle_submit(
        &app,
        lifecycle_ordinary_transaction(
            &app,
            &key,
            vec![Log::new(Level::INFO, "ordinary application".to_owned()).into()],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(app.queue.active_len(), 1);
    assert_ne!(lifecycle_pending_wire(&app), before);
    let response = lifecycle_submit(
        &app,
        lifecycle_ordinary_transaction(
            &app,
            &key,
            vec![
                ApplyThresholdKeyLifecycleCertificateV1 { certificate }.into(),
                Log::new(Level::INFO, "mixed application".to_owned()).into(),
            ],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(app.queue.active_len(), 1);
}

#[tokio::test]
async fn ordinary_sealed_commitment_retains_exact_local_custody_and_requires_one_route() {
    use iroha_data_model::transaction::signed::{
        SealedTransactionCommitmentPayload, SignedSealedTransactionCommitment,
    };

    let (app, key, _, _) = lifecycle_ordinary_fixture(true);
    let network_id = *app.state.network_id_ref();
    let signed = lifecycle_ordinary_transaction(
        &app,
        &key,
        vec![Log::new(Level::INFO, "sealed application".to_owned()).into()],
    );
    let commitment_hash =
        compute_sealed_transaction_commitment(&network_id, &signed, [0x51; 32], 9);
    let entrypoint =
        TransactionEntrypoint::SealedCommitment(SignedSealedTransactionCommitment::sign(
            SealedTransactionCommitmentPayload::new(
                network_id,
                AccountId::new(key.public_key().clone()),
                commitment_hash,
                3,
                9,
                None,
            ),
            key.private_key(),
        ));
    let coordinator = RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL);
    let participant = iroha_core::queue::RouteLeg::new(
        RoutingDecision::new(LaneId::new(9), DataSpaceId::new(9)),
        iroha_core::queue::RouteLegRole::Participant,
    );
    let multi_route = RoutingPlan::native_amx(coordinator, vec![participant]);
    assert!(
        super::ordinary_transaction_ingress::authenticate(&app, &entrypoint, &multi_route)
            .expect_err("sealed commitment must not bypass the single-route guard")
            .contains("multi-route transaction admission is unsupported")
    );
    let before = lifecycle_pending_wire(&app);
    let response = super::handler_post_transaction_entrypoint(
        State(app.clone()),
        HeaderMap::new(),
        None,
        versioned_entrypoint_for_test(entrypoint.clone()),
    )
    .await
    .expect("ordinary sealed commitment returns a classified response")
    .into_response();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(app.queue.active_len(), 1);
    let state = app.state.view();
    let queued = app.queue.all_transactions(&state).collect::<Vec<_>>();
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].entrypoint(), &entrypoint);
    assert_ne!(lifecycle_pending_wire(&app), before);
}

#[test]
fn ordinary_sealed_reveal_authenticates_exact_lifecycle_certificate() {
    let (app, key, _, certificate) = lifecycle_ordinary_fixture(true);
    let network_id = *app.state.network_id_ref();
    let route = RoutingPlan::single(RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL));
    let reveal = |signed: SignedTransaction| {
        let salt = [0x52; 32];
        let commitment = compute_sealed_transaction_commitment(&network_id, &signed, salt, 9);
        TransactionEntrypoint::SealedReveal(SealedTransactionReveal::new(commitment, signed, salt))
    };
    let ordinary = reveal(lifecycle_ordinary_transaction(
        &app,
        &key,
        vec![Log::new(Level::INFO, "revealed application".to_owned()).into()],
    ));
    super::ordinary_transaction_ingress::authenticate(&app, &ordinary, &route)
        .expect("ordinary sealed reveal accepts its single route");
    let exact = reveal(lifecycle_ordinary_transaction(
        &app,
        &key,
        vec![
            ApplyThresholdKeyLifecycleCertificateV1 {
                certificate: certificate.clone(),
            }
            .into(),
        ],
    ));
    super::ordinary_transaction_ingress::authenticate(&app, &exact, &route)
        .expect("exact certified lifecycle reveal authenticates its frozen roster");
    let mixed = reveal(lifecycle_ordinary_transaction(
        &app,
        &key,
        vec![
            ApplyThresholdKeyLifecycleCertificateV1 { certificate }.into(),
            Log::new(Level::INFO, "mixed revealed application".to_owned()).into(),
        ],
    ));
    assert!(
        super::ordinary_transaction_ingress::authenticate(&app, &mixed, &route)
            .expect_err("mixed lifecycle reveal must be rejected")
            .contains("one exact certificate")
    );
}

#[tokio::test]
async fn ordinary_multi_route_application_is_explicitly_unsupported() {
    let (app, key, _, _) = lifecycle_ordinary_fixture(true);
    let before = lifecycle_pending_wire(&app);
    let transaction = lifecycle_ordinary_transaction(
        &app,
        &key,
        vec![Log::new(Level::INFO, "multi-route application".to_owned()).into()],
    );
    let coordinator = RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL);
    let participant = iroha_core::queue::RouteLeg::new(
        RoutingDecision::new(LaneId::new(9), DataSpaceId::new(9)),
        iroha_core::queue::RouteLegRole::Participant,
    );
    let routing_plan = RoutingPlan::native_amx(coordinator, vec![participant]);
    let error = super::ordinary_transaction_ingress::authenticate(
        &app,
        &TransactionEntrypoint::External(transaction),
        &routing_plan,
    )
    .expect_err("multi-route ordinary ingress must refuse before local custody");
    assert!(error.contains("multi-route transaction admission is unsupported"));
    assert_eq!(app.queue.active_len(), 0);
    assert_eq!(lifecycle_pending_wire(&app), before);
}

#[tokio::test]
async fn lifecycle_ordinary_ingress_rejects_invalid_certificate_authority() {
    let (app, key, validators, certificate) = lifecycle_ordinary_fixture(true);
    let before = lifecycle_pending_wire(&app);
    let invalid_outer =
        transaction_with_invalid_signature_for_test(lifecycle_ordinary_transaction(
            &app,
            &key,
            vec![
                ApplyThresholdKeyLifecycleCertificateV1 {
                    certificate: certificate.clone(),
                }
                .into(),
            ],
        ));
    let error = super::submit_signed_transaction_for_ingress(
        app.clone(),
        HeaderMap::new(),
        None,
        invalid_outer,
    )
    .await
    .expect_err("invalid account signature must fail before lifecycle admission");
    assert_eq!(
        torii_response_header(&error.into_response(), "x-iroha-reject-code"),
        Some(SignatureRejectionCode::InvalidSignature.as_str())
    );
    let mut wrong_height = certificate.clone();
    wrong_height.effective_height += 1;
    lifecycle_sign_certificate(&mut wrong_height, &validators);
    let mut wrong_network = certificate.clone();
    wrong_network.network_id = iroha_data_model::NetworkId::from_genesis_hash(
        HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(b"foreign lifecycle network")),
    );
    lifecycle_sign_certificate(&mut wrong_network, &validators);
    let mut wrong_roster = certificate.clone();
    wrong_roster.roster_hash = [0x99; 32];
    lifecycle_sign_certificate(&mut wrong_roster, &validators);
    let mut forged = certificate.clone();
    forged.signatures[0].signature =
        Signature::try_new(validators[3].private_key(), b"forged lifecycle QC").unwrap();
    let mut duplicate = certificate.clone();
    duplicate.signatures[1].signer_index = duplicate.signatures[0].signer_index;
    let mut insufficient = certificate;
    insufficient.signatures.pop();
    for invalid in [
        wrong_height,
        wrong_network,
        wrong_roster,
        forged,
        duplicate,
        insufficient,
    ] {
        let response = lifecycle_submit(
            &app,
            lifecycle_ordinary_transaction(
                &app,
                &key,
                vec![
                    ApplyThresholdKeyLifecycleCertificateV1 {
                        certificate: invalid,
                    }
                    .into(),
                ],
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    assert_eq!(app.queue.active_len(), 0);
    assert_eq!(lifecycle_pending_wire(&app), before);
}

#[tokio::test]
async fn lifecycle_ordinary_ingress_requires_authenticated_parent_and_global_route() {
    for has_parent in [false, true] {
        let (mut app, key, _, certificate) = lifecycle_ordinary_fixture(has_parent);
        let original_authority = app
            .state
            .verify_next_height_threshold_key_lifecycle_certificate_v1(&certificate);
        if has_parent {
            original_authority
                .expect("original applied World authenticates the exact next committee");
        } else {
            assert!(
                original_authority
                    .unwrap_err()
                    .contains("requires a committed parent")
            );
        }
        if has_parent {
            Arc::get_mut(&mut app).unwrap().local_peer_id =
                Some(PeerId::new(key.public_key().clone()));
        }
        let before = lifecycle_pending_wire(&app);
        let response = lifecycle_submit(
            &app,
            lifecycle_ordinary_transaction(
                &app,
                &key,
                vec![ApplyThresholdKeyLifecycleCertificateV1 { certificate }.into()],
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(app.queue.active_len(), 0);
        assert_eq!(lifecycle_pending_wire(&app), before);
    }
    let (app, key, _, certificate) = lifecycle_ordinary_fixture(true);
    let before = lifecycle_pending_wire(&app);
    let transaction = lifecycle_ordinary_transaction(
        &app,
        &key,
        vec![
            ApplyThresholdKeyLifecycleCertificateV1 {
                certificate: certificate.clone(),
            }
            .into(),
        ],
    );
    let error = super::ordinary_transaction_ingress::authenticate(
        &app,
        &TransactionEntrypoint::External(transaction),
        &RoutingPlan::single(RoutingDecision::new(LaneId::new(9), DataSpaceId::new(9))),
    )
    .expect_err("lifecycle certificate must use the exact authenticated global route");
    assert!(error.contains("exact single global control route"));
    assert_eq!(app.queue.active_len(), 0);
    assert_eq!(lifecycle_pending_wire(&app), before);
}
