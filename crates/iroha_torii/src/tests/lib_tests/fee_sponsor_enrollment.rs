// Exact native enrollment reads used by durable application onboarding.
#[tokio::test]
async fn fee_enrollment_point_read_observes_native_revocation_and_exact_registrar_scope() {
    use iroha_data_model::isi::nexus::{
        EnrollFeeSponsorBeneficiary, UnenrollFeeSponsorBeneficiary,
    };
    use iroha_data_model::nexus::FeeSponsorEnrollmentKey;
    use iroha_torii_shared::{FeeSponsorEnrollmentByIdRequest, FeeSponsorEnrollmentByIdResponse};

    let _guard = app_auth_test_guard(crate::app_auth::CanonicalRequestAuthConfig::default());
    let sponsor_key = checked_torii_test_ed25519_keypair(0xd1, "enrollment sponsor");
    let registrar_key = checked_torii_test_ed25519_keypair(0xd2, "enrollment registrar");
    let beneficiary_key = checked_torii_test_ed25519_keypair(0xd3, "enrollment beneficiary");
    let sponsor = AccountId::new(sponsor_key.public_key().clone());
    let registrar = AccountId::new(registrar_key.public_key().clone());
    let beneficiary = AccountId::new(beneficiary_key.public_key().clone());
    let domain = Domain::new(DomainId::try_new("enrollment", "universal").unwrap()).build(&sponsor);
    let accounts = [&sponsor, &registrar, &beneficiary]
        .into_iter()
        .map(|id| Account::new(id.clone()).build(id));
    let app =
        mk_app_state_for_tests_with_world(iroha_core::state::World::with([domain], accounts, []));
    let program = FeeSponsorProgramId::new(sponsor.clone(), "dpn".parse().unwrap());
    let unrelated = FeeSponsorProgramId::new(sponsor.clone(), "other".parse().unwrap());
    register_fee_sponsor_program_for_test(&app, program.clone());
    register_fee_sponsor_program_for_test(&app, unrelated.clone());
    let expected_key = FeeSponsorEnrollmentKey {
        program_id: program.clone(),
        beneficiary: beneficiary.clone(),
    };
    let method = axum::http::Method::POST;
    let uri: axum::http::Uri = route_catalog::fees::SPONSOR_ENROLLMENT_BY_ID_PATH
        .parse()
        .unwrap();
    let body = norito::json::to_vec(&FeeSponsorEnrollmentByIdRequest::new(
        &program,
        &beneficiary,
    ))
    .unwrap();

    // A signature alone, beneficiary identity, or an unrelated program grant is insufficient.
    grant_account_permissions_for_test(
        &app,
        &registrar,
        [
            Permission::from(CanReadAllLedgerData),
            onboarding_fee_sponsor_enrollment_permission(&unrelated),
        ],
    );
    for (caller, keypair) in [
        (&registrar, &registrar_key),
        (&beneficiary, &beneficiary_key),
    ] {
        let headers = signed_app_headers(caller, keypair, &method, &uri, &body);
        let response = handler_fee_sponsor_enrollment_by_id(
            State(app.clone()),
            method.clone(),
            uri.clone(),
            headers,
            body.clone().into(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    let unsigned = handler_fee_sponsor_enrollment_by_id(
        State(app.clone()),
        method.clone(),
        uri.clone(),
        HeaderMap::new(),
        body.clone().into(),
    )
    .await
    .unwrap();
    assert_eq!(unsigned.status(), StatusCode::UNAUTHORIZED);
    grant_account_permissions_for_test(
        &app,
        &registrar,
        [onboarding_fee_sponsor_enrollment_permission(&program)],
    );

    // Both admitted callers see explicit absent -> present -> absent after native writes.
    for enrolled in [false, true, false] {
        if enrolled
            || app
                .state
                .world_view()
                .fee_sponsor_enrollments()
                .get(&expected_key)
                .is_some()
        {
            let header = BlockHeader::new(
                NonZeroU64::new(next_block_height(&app)).unwrap(),
                None,
                None,
                0,
                0,
            );
            let mut block = app.state.block(header);
            let mut transaction = block.transaction();
            if enrolled {
                EnrollFeeSponsorBeneficiary {
                    program_id: program.clone(),
                    beneficiary: beneficiary.clone(),
                }
                .execute(&sponsor, &mut transaction)
                .unwrap();
            } else {
                UnenrollFeeSponsorBeneficiary {
                    program_id: program.clone(),
                    beneficiary: beneficiary.clone(),
                }
                .execute(&sponsor, &mut transaction)
                .unwrap();
            }
            transaction.apply();
            block.commit_world_overlay_for_testing().unwrap();
        }
        for (caller, keypair) in [(&sponsor, &sponsor_key), (&registrar, &registrar_key)] {
            let headers = signed_app_headers(caller, keypair, &method, &uri, &body);
            let response = handler_fee_sponsor_enrollment_by_id(
                State(app.clone()),
                method.clone(),
                uri.clone(),
                headers,
                body.clone().into(),
            )
            .await
            .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let bytes = axum::body::to_bytes(response.into_body(), 8192)
                .await
                .unwrap();
            let observed: FeeSponsorEnrollmentByIdResponse =
                norito::json::from_slice(&bytes).unwrap();
            assert_eq!(observed.key, expected_key);
            assert_eq!(observed.enrollment.is_some(), enrolled);
            if let Some(row) = observed.enrollment {
                assert_eq!(row.key, expected_key);
                assert!(row.enrolled_at_height > 0);
            }
        }
    }
    // Revoking the exact registrar grant takes effect in the current read view.
    let header = BlockHeader::new(
        NonZeroU64::new(next_block_height(&app)).unwrap(),
        None,
        None,
        0,
        0,
    );
    let mut block = app.state.block(header);
    let mut transaction = block.transaction();
    assert!(
        transaction
            .world_mut_for_testing()
            .remove_account_permission(
                &registrar,
                &onboarding_fee_sponsor_enrollment_permission(&program)
            )
    );
    transaction.apply();
    block.commit_world_overlay_for_testing().unwrap();
    let headers = signed_app_headers(&registrar, &registrar_key, &method, &uri, &body);
    let response = handler_fee_sponsor_enrollment_by_id(
        State(app.clone()),
        method.clone(),
        uri.clone(),
        headers,
        body.clone().into(),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let missing_program = FeeSponsorProgramId::new(sponsor.clone(), "missing".parse().unwrap());
    let absent_program_body = norito::json::to_vec(&FeeSponsorEnrollmentByIdRequest::new(
        &missing_program,
        &beneficiary,
    ))
    .unwrap();
    let headers = signed_app_headers(&sponsor, &sponsor_key, &method, &uri, &absent_program_body);
    let response = handler_fee_sponsor_enrollment_by_id(
        State(app.clone()),
        method.clone(),
        uri.clone(),
        headers,
        absent_program_body.into(),
    )
    .await
    .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "missing program must not be an absent enrollment"
    );
    for malformed in [
        format!(r#"{{"program_id":"{program} ","beneficiary":"{beneficiary}"}}"#),
        format!(r#"{{"program_id":"{program}","beneficiary":" {beneficiary}"}}"#),
        format!(r#"{{"program_id":"{program}","beneficiary":"{beneficiary}","extra":true}}"#),
        format!(
            r#"{{"program_id":"{program}","beneficiary":"{beneficiary}","beneficiary":"{beneficiary}"}}"#
        ),
    ] {
        let headers =
            signed_app_headers(&sponsor, &sponsor_key, &method, &uri, malformed.as_bytes());
        let response = handler_fee_sponsor_enrollment_by_id(
            State(app.clone()),
            method.clone(),
            uri.clone(),
            headers,
            malformed.into_bytes().into(),
        )
        .await
        .map_or_else(IntoResponse::into_response, |response| response);
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn fee_enrollment_point_read_rejects_expired_replayed_and_substituted_authentication() {
    use iroha_torii_shared::{FeeSponsorEnrollmentByIdRequest, FeeSponsorEnrollmentByIdResponse};

    let _guard = app_auth_test_guard(crate::app_auth::CanonicalRequestAuthConfig::default());
    let sponsor_key = checked_torii_test_ed25519_keypair(0xd4, "enrollment auth sponsor");
    let sponsor = AccountId::new(sponsor_key.public_key().clone());
    let beneficiary = AccountId::new(
        checked_torii_test_ed25519_keypair(0xd5, "future enrollment beneficiary")
            .public_key()
            .clone(),
    );
    let app = mk_app_state_for_tests_with_world(world_with_account(&sponsor));
    let program = FeeSponsorProgramId::new(sponsor.clone(), "dpn".parse().unwrap());
    register_fee_sponsor_program_for_test(&app, program.clone());
    let method = axum::http::Method::POST;
    let uri: axum::http::Uri = route_catalog::fees::SPONSOR_ENROLLMENT_BY_ID_PATH
        .parse()
        .unwrap();
    let body = norito::json::to_vec(&FeeSponsorEnrollmentByIdRequest::new(
        &program,
        &beneficiary,
    ))
    .unwrap();
    let headers = signed_app_headers(&sponsor, &sponsor_key, &method, &uri, &body);
    let response = handler_fee_sponsor_enrollment_by_id(
        State(app.clone()),
        method.clone(),
        uri.clone(),
        headers.clone(),
        body.clone().into(),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 8192)
        .await
        .unwrap();
    let observed: FeeSponsorEnrollmentByIdResponse = norito::json::from_slice(&bytes).unwrap();
    assert_eq!(observed.key.program_id, program);
    assert_eq!(observed.key.beneficiary, beneficiary);
    assert!(
        observed.enrollment.is_none(),
        "a future beneficiary is exactly absent in an existing program"
    );
    let replay = handler_fee_sponsor_enrollment_by_id(
        State(app.clone()),
        method.clone(),
        uri.clone(),
        headers,
        body.clone().into(),
    )
    .await
    .map_or_else(IntoResponse::into_response, |response| response);
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);

    let mut expired = signed_app_headers(&sponsor, &sponsor_key, &method, &uri, &body);
    let timestamp_ms = 1;
    let nonce = expired.get(crate::HEADER_NONCE).unwrap().to_str().unwrap();
    let message = crate::canonical_network_request_signature_message(
        app.state.network_id_ref(),
        &method,
        &uri,
        &body,
        timestamp_ms,
        nonce,
    )
    .unwrap();
    let signature = iroha_crypto::Signature::try_new(sponsor_key.private_key(), &message).unwrap();
    expired.insert(
        crate::HEADER_TIMESTAMP_MS,
        timestamp_ms.to_string().parse().unwrap(),
    );
    expired.insert(
        crate::HEADER_SIGNATURE,
        crate::signature_header_value(&signature)
            .unwrap()
            .parse()
            .unwrap(),
    );
    let expired = handler_fee_sponsor_enrollment_by_id(
        State(app.clone()),
        method.clone(),
        uri.clone(),
        expired,
        body.clone().into(),
    )
    .await
    .map_or_else(IntoResponse::into_response, |response| response);
    assert_eq!(expired.status(), StatusCode::UNAUTHORIZED);

    let headers = signed_app_headers(&sponsor, &sponsor_key, &method, &uri, &body);
    let substituted =
        norito::json::to_vec(&FeeSponsorEnrollmentByIdRequest::new(&program, &sponsor)).unwrap();
    let substituted = handler_fee_sponsor_enrollment_by_id(
        State(app.clone()),
        method.clone(),
        uri.clone(),
        headers,
        substituted.into(),
    )
    .await
    .map_or_else(IntoResponse::into_response, |response| response);
    assert_eq!(substituted.status(), StatusCode::UNAUTHORIZED);
    assert!(app.state.world_view().fee_sponsor_enrollments().is_empty());
}
