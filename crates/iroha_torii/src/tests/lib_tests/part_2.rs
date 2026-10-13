fn assert_onboarding_readiness_blocked(
    app: &SharedAppState,
    signer: &AccountOnboardingSigner,
    message: &str,
) {
    let report = validate_account_onboarding_readiness(app.state.as_ref(), signer)
        .expect("read original onboarding readiness");
    assert_ne!(
        report.status,
        iroha_data_model::alias_setup::AliasSetupStatusV1::Ready,
        "{message}: readiness unexpectedly succeeded: {report:?}"
    );
    assert!(!report.diagnostics.is_empty(), "{message}");
}
fn assert_onboarding_readiness_ready(app: &SharedAppState, signer: &AccountOnboardingSigner) {
    let report = validate_account_onboarding_readiness(app.state.as_ref(), signer)
        .expect("read original onboarding readiness");
    assert_eq!(
        report.status,
        iroha_data_model::alias_setup::AliasSetupStatusV1::Ready,
        "{report:?}"
    );
    assert!(report.diagnostics.is_empty());
}
#[test]
fn onboarding_readiness_is_pending_while_joining_state_is_empty() {
    let key_pair =
        checked_torii_test_ed25519_keypair(0xA2, "derive joining onboarding readiness fixture key");
    let app = mk_app_state_for_tests();
    let signer = onboarding_alias_signer_for_test(&key_pair);
    let report = validate_account_onboarding_readiness(app.state.as_ref(), &signer)
        .expect("read original onboarding readiness");
    assert_eq!(
        report.status,
        iroha_data_model::alias_setup::AliasSetupStatusV1::Pending,
        "{report:?}"
    );
    assert!(
        report
            .diagnostics
            .iter()
            .any(|diagnostic| { diagnostic.code == "alias.onboarding.payment_asset_missing" })
    );
}
#[test]
fn onboarding_readiness_defers_original_policy_read_without_publishing_blocked_report() {
    let key_pair =
        checked_torii_test_ed25519_keypair(0xA2, "derive original readiness refusal fixture key");
    let app = mk_app_state_for_tests();
    let signer = onboarding_alias_signer_for_test(&key_pair);
    let key = iroha_core::sns::policy_storage_key(iroha_data_model::sns::ACCOUNT_ALIAS_SUFFIX_ID);
    let original = app
        .state
        .world_view()
        .smart_contract_state()
        .get(&key)
        .unwrap()
        .clone();
    let expected = validate_account_onboarding_readiness(app.state.as_ref(), &signer).unwrap();
    assert_eq!(
        expected.status,
        iroha_data_model::alias_setup::AliasSetupStatusV1::Pending
    );
    let refused = norito::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
        || validate_account_onboarding_readiness(app.state.as_ref(), &signer),
    );
    assert!(
        matches!(
            &refused,
            Err(Error::Query(iroha_data_model::ValidationFail::QueryFailed(
                iroha_data_model::query::error::QueryExecutionFail::GasBudgetExceeded
            )))
        ),
        "{refused:?}"
    );
    assert_eq!(
        refused.unwrap_err().into_response().status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        app.state
            .world_view()
            .smart_contract_state()
            .get(&key)
            .unwrap(),
        &original
    );
    assert_eq!(
        validate_account_onboarding_readiness(app.state.as_ref(), &signer).unwrap(),
        expected
    );
}
#[test]
fn onboarding_permission_target_matches_canonical_tokens_and_defers_local_construction() {
    use iroha_executor_data_model::permission::dpn::DpnAdmin;
    let unit = Permission::from(DpnAdmin);
    assert_eq!(torii_permission_target(DpnAdmin).unwrap(), unit);
    // Even the unit token retains a four-byte canonical output before its Arc owner.
    let refused = norito::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
        || torii_permission_target(DpnAdmin),
    );
    assert!(
        matches!(
            refused,
            Err(Error::Query(iroha_data_model::ValidationFail::QueryFailed(
                iroha_data_model::query::error::QueryExecutionFail::GasBudgetExceeded
            )))
        ),
        "{refused:?}"
    );
    assert_eq!(torii_permission_target(DpnAdmin).unwrap(), unit);
    let key_pair = checked_torii_test_ed25519_keypair(0x97, "derive onboarding token fixture key");
    let authority = AccountId::new(key_pair.public_key().clone());
    let token = CanEnrollFeeSponsorProgram {
        program_id: FeeSponsorProgramId::new(authority, "original".parse().unwrap()),
    };
    let expected = Permission::from(token.clone());
    assert_eq!(torii_permission_target(token.clone()).unwrap(), expected);
    let original = token.clone();
    let refused = norito::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
        || torii_permission_target(original),
    );
    assert!(
        matches!(
            refused,
            Err(Error::Query(iroha_data_model::ValidationFail::QueryFailed(
                iroha_data_model::query::error::QueryExecutionFail::GasBudgetExceeded
            )))
        ),
        "{refused:?}"
    );
    assert_eq!(torii_permission_target(token).unwrap(), expected);
}
#[test]
fn onboarding_account_diagnostic_preserves_original_address_refusal() {
    let key_pair =
        checked_torii_test_ed25519_keypair(0x98, "derive onboarding diagnostic fixture key");
    let authority = AccountId::new(key_pair.public_key().clone());
    let expected = authority.to_string();
    assert_eq!(onboarding_account_literal(&authority).unwrap(), expected);
    let refused = norito::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
        || onboarding_account_literal(&authority),
    );
    assert!(
        matches!(
            refused,
            Err(Error::Query(iroha_data_model::ValidationFail::QueryFailed(
                iroha_data_model::query::error::QueryExecutionFail::GasBudgetExceeded
            )))
        ),
        "{refused:?}"
    );
    assert_eq!(onboarding_account_literal(&authority).unwrap(), expected);
}
#[test]
fn onboarding_readiness_payment_asset_mismatch_is_blocked_while_joining_state_is_empty() {
    let key_pair = checked_torii_test_ed25519_keypair(
        0xA9,
        "derive joining payment-asset mismatch fixture key",
    );
    let app = mk_app_state_for_tests();
    let mut policy = iroha_core::sns::policy_by_id(
        &app.state.world_view(),
        iroha_data_model::sns::ACCOUNT_ALIAS_SUFFIX_ID,
    )
    .expect("read seeded account-alias policy")
    .expect("State initialization seeds the account-alias policy");
    let other_asset = recipient_lookup_aed_definition_for_test().to_string();
    assert_ne!(policy.payment_asset_id, other_asset);
    policy.payment_asset_id = other_asset.clone();
    for tier in &mut policy.pricing {
        tier.base_price.asset_id = other_asset.clone();
    }
    let header = BlockHeader::new(NonZeroU64::new(1).expect("height>0"), None, None, 0, 0);
    let mut block = app.state.block(header);
    let mut stx = block.transaction();
    stx.world_mut_for_testing()
        .smart_contract_state_mut_for_testing()
        .insert(
            iroha_core::sns::policy_storage_key(iroha_data_model::sns::ACCOUNT_ALIAS_SUFFIX_ID),
            norito::codec::Encode::encode(&policy),
        );
    stx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("install mismatched policy without finalizing a block");
    assert!(
        app.state
            .view()
            .latest_block()
            .expect("funded canonical history read")
            .is_none()
    );
    assert!(app.state.world_view().accounts().iter().next().is_none());
    assert!(matches!(
        iroha_core::sns::ensure_namespace_policy_payment_asset_matches_configured(
            &app.state.world_view(),
            iroha_core::sns::SnsNamespace::AccountAlias,
            &app.state.nexus_snapshot().fees.fee_asset_id,
        ),
        Err(iroha_core::sns::SnsError::Conflict(_))
    ));
    let signer = onboarding_alias_signer_for_test(&key_pair);
    let report = validate_account_onboarding_readiness(app.state.as_ref(), &signer)
        .expect("read original onboarding readiness");
    assert_eq!(
        report.status,
        iroha_data_model::alias_setup::AliasSetupStatusV1::Blocked,
        "{report:?}"
    );
    assert!(
        report
            .diagnostics
            .iter()
            .any(|diagnostic| { diagnostic.code == "alias.onboarding.payment_asset_mismatch" })
    );
}
#[test]
fn onboarding_alias_credential_domain_rejects_missing_exact_manage_authority() {
    let key_pair =
        checked_torii_test_ed25519_keypair(0x96, "derive onboarding credential domain fixture key");
    let authority = AccountId::new(key_pair.public_key().clone());
    let app = onboarding_alias_test_app(&authority, &authority);
    let hbl = DomainId::try_new("hbl", "sbp").expect("HBL domain");
    let mut signer = onboarding_alias_signer_for_test(&key_pair);
    signer
        .api_token_hashes_by_domain
        .insert(hbl, vec![[0xA5; 32]]);
    assert_onboarding_readiness_blocked(
        &app,
        &signer,
        "domain ownership must not substitute for exact credential-domain manage authority",
    );
}
#[test]
fn onboarding_readiness_rejects_unknown_additional_permission() {
    let key_pair = checked_torii_test_ed25519_keypair(
        0xA1,
        "derive onboarding permission readiness fixture key",
    );
    let authority = AccountId::new(key_pair.public_key().clone());
    let app = onboarding_alias_test_app(&authority, &authority);
    let mut signer = onboarding_alias_signer_for_test(&key_pair);
    signer
        .allowed_permissions
        .insert("DefinitelyUnknownPermission".to_owned());
    let report = validate_account_onboarding_readiness(app.state.as_ref(), &signer)
        .expect("read original onboarding readiness");
    assert_eq!(
        report.status,
        iroha_data_model::alias_setup::AliasSetupStatusV1::Blocked
    );
    assert!(
        report.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "alias.onboarding.additional_permission_unknown"
        })
    );
}
fn declare_onboarding_dpn_permissions_for_test(app: &SharedAppState) {
    let height = next_block_height(app);
    let header = BlockHeader::new(NonZeroU64::new(height).expect("height>0"), None, None, 0, 0);
    let mut block = app.state.block(header);
    let mut stx = block.transaction();
    let world = stx.world_mut_for_testing();
    let current = world.executor_data_model();
    let mut permissions = current.permissions().clone();
    permissions.extend(["DpnUser".to_owned(), "DpnAdmin".to_owned()]);
    let model = iroha_data_model::executor::ExecutorDataModel::new(
        current.parameters().clone(),
        current.instructions().clone(),
        permissions,
        current.schema().clone(),
    );
    world.apply_executor_data_model(model);
    stx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("declare onboarding DPN permissions without a synthetic empty block");
}
#[test]
fn onboarding_readiness_dpn_user_requires_exact_direct_admin() {
    use iroha_executor_data_model::permission::dpn::DpnAdmin;

    let key_pair =
        checked_torii_test_ed25519_keypair(0xA3, "derive DPN onboarding authority fixture key");
    let authority = AccountId::new(key_pair.public_key().clone());
    let scoped_admin = Permission::new(
        "DpnAdmin".to_owned(),
        iroha_primitives::json::Json::new(norito::json!({ "scope": 0 })),
    );
    for (label, permission, ready) in [
        ("missing", None, false),
        ("scoped", Some(scoped_admin), false),
        ("direct", Some(Permission::from(DpnAdmin)), true),
    ] {
        let app = onboarding_alias_test_app(&authority, &authority);
        declare_onboarding_dpn_permissions_for_test(&app);
        grant_account_permissions_for_test(&app, &authority, permission);
        let mut signer = onboarding_alias_signer_for_test(&key_pair);
        signer.allowed_permissions.insert("DpnUser".to_owned());
        let report = validate_account_onboarding_readiness(app.state.as_ref(), &signer)
            .expect("read original onboarding readiness");
        if ready {
            assert_onboarding_readiness_ready(&app, &signer);
        } else {
            assert_eq!(
                report.status,
                iroha_data_model::alias_setup::AliasSetupStatusV1::Blocked,
                "{label}: {report:?}"
            );
            assert_eq!(report.diagnostics.len(), 1, "{label}: {report:?}");
            assert_eq!(
                report.diagnostics[0].code, "alias.onboarding.dpn_user_grant_authority_missing",
                "{label}: {report:?}"
            );
        }
    }
}
#[test]
fn onboarding_readiness_dpn_user_rejects_role_derived_admin() {
    use iroha_executor_data_model::permission::dpn::DpnAdmin;

    let key_pair = checked_torii_test_ed25519_keypair(
        0xA4,
        "derive role DPN onboarding authority fixture key",
    );
    let authority = AccountId::new(key_pair.public_key().clone());
    let admin = Permission::from(DpnAdmin);
    let app =
        onboarding_alias_test_app_with_role_permissions(&authority, &authority, [admin.clone()]);
    declare_onboarding_dpn_permissions_for_test(&app);
    assert!(torii_account_has_permission(
        &app.state.world_view(),
        &authority,
        &admin,
    ));
    assert!(
        !app.state
            .world_view()
            .account_contains_inherent_permission(&authority, &admin)
    );
    let mut signer = onboarding_alias_signer_for_test(&key_pair);
    signer.allowed_permissions.insert("DpnUser".to_owned());
    let report = validate_account_onboarding_readiness(app.state.as_ref(), &signer)
        .expect("read original onboarding readiness");
    assert_eq!(
        report.status,
        iroha_data_model::alias_setup::AliasSetupStatusV1::Blocked,
        "{report:?}"
    );
    assert_eq!(report.diagnostics.len(), 1, "{report:?}");
    assert_eq!(
        report.diagnostics[0].code,
        "alias.onboarding.dpn_user_grant_authority_missing"
    );
}
#[test]
fn onboarding_readiness_default_permissions_do_not_require_dpn_admin() {
    let key_pair =
        checked_torii_test_ed25519_keypair(0xA7, "derive default onboarding authority fixture key");
    let authority = AccountId::new(key_pair.public_key().clone());
    let app = onboarding_alias_test_app(&authority, &authority);
    let signer = onboarding_alias_signer_for_test(&key_pair);
    assert!(signer.allowed_permissions.is_empty());
    assert_onboarding_readiness_ready(&app, &signer);
}
#[test]
fn onboarding_readiness_dpn_user_is_pending_while_joining_state_is_empty() {
    let key_pair =
        checked_torii_test_ed25519_keypair(0xA8, "derive joining DPN onboarding fixture key");
    let app = mk_app_state_for_tests();
    let mut signer = onboarding_alias_signer_for_test(&key_pair);
    signer.allowed_permissions.insert("DpnUser".to_owned());
    let report = validate_account_onboarding_readiness(app.state.as_ref(), &signer)
        .expect("read original onboarding readiness");
    assert_eq!(
        report.status,
        iroha_data_model::alias_setup::AliasSetupStatusV1::Pending,
        "{report:?}"
    );
    assert!(report.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "alias.onboarding.dpn_user_grant_authority_missing"
    }));
    assert!(
        report
            .diagnostics
            .iter()
            .any(|diagnostic| { diagnostic.code == "alias.onboarding.payment_asset_missing" })
    );
}
#[test]
fn onboarding_alias_credential_domains_accept_exact_direct_permissions() {
    let key_pair = checked_torii_test_ed25519_keypair(
        0x97,
        "derive exact onboarding credential domain fixture key",
    );
    let authority = AccountId::new(key_pair.public_key().clone());
    let app = onboarding_alias_test_app(&authority, &authority);
    let hbl = DomainId::try_new("hbl", "sbp").expect("HBL domain");
    let ubl = DomainId::try_new("ubl", "sbp").expect("UBL domain");
    let fee_sponsor_program_id = onboarding_fee_sponsor_program_for_test(&authority);
    register_fee_sponsor_program_for_test(&app, fee_sponsor_program_id.clone());
    grant_account_permissions_for_test(
        &app,
        &authority,
        onboarding_credential_domain_permissions(&hbl)
            .into_iter()
            .chain(onboarding_credential_domain_permissions(&ubl))
            .chain([onboarding_fee_sponsor_enrollment_permission(
                &fee_sponsor_program_id,
            )]),
    );
    let mut signer = onboarding_alias_signer_for_test(&key_pair);
    signer.fee_sponsor_program_id = Some(fee_sponsor_program_id);
    signer
        .api_token_hashes_by_domain
        .insert(hbl, vec![[0xA5; 32]]);
    signer
        .api_token_hashes_by_domain
        .insert(ubl, vec![[0xA6; 32]]);
    assert_onboarding_readiness_ready(&app, &signer);
}
#[test]
fn onboarding_alias_credential_domains_accept_exact_role_permissions() {
    let key_pair = checked_torii_test_ed25519_keypair(
        0x99,
        "derive role-backed onboarding credential domain fixture key",
    );
    let owner_key_pair = checked_torii_test_ed25519_keypair(
        0x9A,
        "derive onboarding credential domain owner fixture key",
    );
    let authority = AccountId::new(key_pair.public_key().clone());
    let domain_owner = AccountId::new(owner_key_pair.public_key().clone());
    let hbl = DomainId::try_new("hbl", "sbp").expect("HBL domain");
    let ubl = DomainId::try_new("ubl", "sbp").expect("UBL domain");
    let fee_sponsor_program_id = onboarding_fee_sponsor_program_for_test(&domain_owner);
    let app = onboarding_alias_test_app_with_role_permissions(
        &authority,
        &domain_owner,
        onboarding_credential_domain_permissions(&hbl)
            .into_iter()
            .chain(onboarding_credential_domain_permissions(&ubl))
            .chain([onboarding_fee_sponsor_enrollment_permission(
                &fee_sponsor_program_id,
            )]),
    );
    register_fee_sponsor_program_for_test(&app, fee_sponsor_program_id.clone());
    let mut signer = onboarding_alias_signer_for_test(&key_pair);
    signer.fee_sponsor_program_id = Some(fee_sponsor_program_id);
    signer
        .api_token_hashes_by_domain
        .insert(hbl, vec![[0xA5; 32]]);
    signer
        .api_token_hashes_by_domain
        .insert(ubl, vec![[0xA6; 32]]);
    assert_onboarding_readiness_ready(&app, &signer);
}
#[test]
fn onboarding_alias_fee_sponsor_rejects_missing_or_mismatched_enrollment_permission() {
    let key_pair = checked_torii_test_ed25519_keypair(
        0x9C,
        "derive onboarding fee sponsor authority fixture key",
    );
    let sponsor_key_pair = checked_torii_test_ed25519_keypair(
        0x9D,
        "derive onboarding fee sponsor account fixture key",
    );
    let authority = AccountId::new(key_pair.public_key().clone());
    let sponsor_account = AccountId::new(sponsor_key_pair.public_key().clone());
    let hbl = DomainId::try_new("hbl", "sbp").expect("HBL domain");
    let fee_sponsor_program_id = onboarding_fee_sponsor_program_for_test(&sponsor_account);
    let cases = [
        ("missing enrollment", None),
        (
            "cross-program enrollment",
            Some(Permission::from(CanEnrollFeeSponsorProgram {
                program_id: FeeSponsorProgramId::new(
                    sponsor_account.clone(),
                    "other".parse().expect("other program name"),
                ),
            })),
        ),
        (
            "cross-sponsor enrollment",
            Some(Permission::from(CanEnrollFeeSponsorProgram {
                program_id: FeeSponsorProgramId::new(
                    authority.clone(),
                    fee_sponsor_program_id.name.clone(),
                ),
            })),
        ),
    ];
    for (label, enrollment) in cases {
        let app = onboarding_alias_test_app(&authority, &sponsor_account);
        register_fee_sponsor_program_for_test(&app, fee_sponsor_program_id.clone());
        let mut permissions = onboarding_credential_domain_permissions(&hbl).to_vec();
        permissions.extend(enrollment);
        grant_account_permissions_for_test(&app, &authority, permissions);
        let mut signer = onboarding_alias_signer_for_test(&key_pair);
        signer.fee_sponsor_program_id = Some(fee_sponsor_program_id.clone());
        signer
            .api_token_hashes_by_domain
            .insert(hbl.clone(), vec![[0xA5; 32]]);
        assert_onboarding_readiness_blocked(
            &app,
            &signer,
            &format!("{label} must block onboarding readiness"),
        );
    }
}
#[test]
fn onboarding_alias_fee_sponsor_rejects_unregistered_program() {
    let key_pair = checked_torii_test_ed25519_keypair(
        0x9E,
        "derive unregistered onboarding fee sponsor fixture key",
    );
    let sponsor_key_pair = checked_torii_test_ed25519_keypair(
        0x9F,
        "derive absent onboarding fee sponsor fixture key",
    );
    let authority = AccountId::new(key_pair.public_key().clone());
    let absent_sponsor = AccountId::new(sponsor_key_pair.public_key().clone());
    let app = onboarding_alias_test_app(&authority, &authority);
    let mut signer = onboarding_alias_signer_for_test(&key_pair);
    signer.fee_sponsor_program_id = Some(onboarding_fee_sponsor_program_for_test(&absent_sponsor));
    assert_onboarding_readiness_blocked(
        &app,
        &signer,
        "an unregistered configured onboarding fee sponsor program must fail startup validation",
    );
}
#[test]
fn onboarding_alias_credential_domain_rejects_unregistered_domain() {
    let key_pair = checked_torii_test_ed25519_keypair(
        0x98,
        "derive unregistered onboarding credential domain fixture key",
    );
    let authority = AccountId::new(key_pair.public_key().clone());
    let app = onboarding_alias_test_app(&authority, &authority);
    let other = DomainId::try_new("other", "sbp").expect("other domain");
    let mut signer = onboarding_alias_signer_for_test(&key_pair);
    signer
        .api_token_hashes_by_domain
        .insert(other, vec![[0xA5; 32]]);
    assert_onboarding_readiness_blocked(
        &app,
        &signer,
        "unregistered credential domain must fail startup validation",
    );
}
#[test]
fn alias_resolve_domain_permission_is_exact_and_does_not_widen_to_dataspace() {
    let key_pair = checked_torii_test_ed25519_keypair(
        0x96,
        "derive exact alias domain resolution fixture key",
    );
    let authority = AccountId::new(key_pair.public_key().clone());
    let app = onboarding_alias_test_app(&authority, &authority);
    let hbl = DomainId::try_new("hbl", "sbp").expect("HBL domain");
    grant_account_permissions_for_test(
        &app,
        &authority,
        [Permission::from(CanResolveAccountAlias {
            scope: AccountAliasPermissionScope::Domain(hbl),
        })],
    );
    let nexus = app.state.nexus_snapshot();
    let catalog = &nexus.dataspace_catalog;
    let hbl_alias =
        AccountAlias::from_literal("payee@hbl.sbp", catalog).expect("HBL alias should parse");
    let ubl_alias =
        AccountAlias::from_literal("payee@ubl.sbp", catalog).expect("UBL alias should parse");
    let domainless_alias = AccountAlias::from_literal("payee@sbp", catalog)
        .expect("domainless SBP alias should parse");
    let state_view = app.state.view();
    let world = state_view.world();
    assert!(torii_authority_can_resolve_account_alias(world, &authority, &hbl_alias).unwrap());
    assert!(
        iroha_core::alias::authority_can_resolve_account_alias(world, &authority, &hbl_alias)
            .unwrap()
    );
    for alias in [&ubl_alias, &domainless_alias] {
        assert!(!torii_authority_can_resolve_account_alias(world, &authority, alias).unwrap());
        assert!(
            !iroha_core::alias::authority_can_resolve_account_alias(world, &authority, alias)
                .unwrap()
        );
    }
}
#[test]
fn alias_permission_routes_preserve_json_refusal_without_denial_or_partial_output() {
    let key_pair =
        checked_torii_test_ed25519_keypair(0x96, "derive original alias route refusal fixture key");
    let authority = AccountId::new(key_pair.public_key().clone());
    let app = onboarding_alias_test_app(&authority, &authority);
    let hbl = DomainId::try_new("hbl", "sbp").unwrap();
    let permission = Permission::from(CanResolveAccountAlias {
        scope: AccountAliasPermissionScope::Domain(hbl),
    });
    grant_account_permissions_for_test(&app, &authority, [permission.clone()]);
    let alias = AccountAlias::from_literal(
        "payee@hbl.sbp",
        &app.state.nexus_snapshot().dataspace_catalog,
    )
    .unwrap();
    let view = app.state.view();
    assert!(torii_authority_can_resolve_account_alias(view.world(), &authority, &alias).unwrap());
    let result = norito::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
        || torii_authority_can_resolve_account_alias(view.world(), &authority, &alias),
    );
    assert!(
        matches!(
            &result,
            Err(Error::Query(iroha_data_model::ValidationFail::QueryFailed(
                iroha_data_model::query::error::QueryExecutionFail::GasBudgetExceeded
            )))
        ),
        "{result:?}"
    );
    assert_eq!(
        result.unwrap_err().into_response().status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert!(
        view.world()
            .account_permissions_iter(&authority)
            .unwrap()
            .any(|grant| grant == &permission)
    );
    assert!(torii_authority_can_resolve_account_alias(view.world(), &authority, &alias).unwrap());
}
#[test]
fn alias_result_filter_never_publishes_partial_output_after_original_scope_refusal() {
    let key_pair =
        checked_torii_test_ed25519_keypair(0x96, "derive original filtered alias fixture key");
    let authority = AccountId::new(key_pair.public_key().clone());
    let app = onboarding_alias_test_app(&authority, &authority);
    grant_account_permissions_for_test(
        &app,
        &authority,
        [Permission::from(CanResolveAccountAlias {
            scope: AccountAliasPermissionScope::Domain(DomainId::try_new("hbl", "sbp").unwrap()),
        })],
    );
    let payload = norito::json!({"items": [{"alias": "payee@hbl.sbp"}], "total": 1});
    assert_eq!(
        filter_permission_opened_alias_lookup_payload(&app, &authority, payload.clone()).unwrap(),
        payload
    );
    let attempt = payload.clone();
    let refused = norito::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
        || filter_permission_opened_alias_lookup_payload(&app, &authority, attempt),
    );
    assert_eq!(
        refused.unwrap_err().status(),
        StatusCode::TOO_MANY_REQUESTS,
        "a local refusal cannot publish a successful empty or partially filtered response"
    );
    assert_eq!(
        filter_permission_opened_alias_lookup_payload(&app, &authority, payload.clone()).unwrap(),
        payload
    );
    let malformed = norito::json!({"items": [{"alias": 7}], "total": 1});
    assert_eq!(
        filter_permission_opened_alias_lookup_payload(&app, &authority, malformed)
            .unwrap_err()
            .status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    let denied = norito::json!({"items": [{"alias": "payee@ubl.sbp"}], "total": 1});
    assert!(
        filter_permission_opened_alias_lookup_payload(&app, &authority, denied)
            .unwrap()
            .get("items")
            .unwrap()
            .as_array()
            .unwrap()
            .is_empty(),
        "actual permission denial still filters"
    );
}
#[test]
fn exact_alias_route_grant_decoder_defers_original_payload_and_retries() {
    let dataspace = DataSpaceId::new(42);
    let alias = iroha_data_model::alias_setup::ResolvedAccountAliasV1::new(
        "merchant@paynet".parse().unwrap(),
        dataspace,
    );
    let permission = Permission::from(CanResolveAccountAlias {
        scope: AccountAliasPermissionScope::Alias(alias),
    });
    let bytes = permission.payload().as_ref().to_owned();
    let request = routing::AliasLookupByAccountRequestDto {
        account_id: String::new(),
        dataspace: None,
        domain: None,
    };
    assert!(torii_exact_alias_permission_matches_route(&permission, dataspace, &request).unwrap());
    let refused = norito::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
        || torii_exact_alias_permission_matches_route(&permission, dataspace, &request),
    );
    assert!(matches!(
        refused,
        Err(Error::Query(iroha_data_model::ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::GasBudgetExceeded
        )))
    ));
    assert_eq!(permission.payload().as_ref(), bytes);
    assert!(torii_exact_alias_permission_matches_route(&permission, dataspace, &request).unwrap());
    assert!(
        !torii_exact_alias_permission_matches_route(&permission, DataSpaceId::new(43), &request)
            .unwrap()
    );
    let wrong_domain = routing::AliasLookupByAccountRequestDto {
        domain: Some("bank".to_owned()),
        ..request
    };
    assert!(
        !torii_exact_alias_permission_matches_route(&permission, dataspace, &wrong_domain).unwrap()
    );
    for raw in ["null", "false", "{}", r#"{"scope":null}"#] {
        let malformed = Permission::new(
            "CanResolveAccountAlias".to_owned(),
            iroha_primitives::json::Json::from_raw_json(raw.to_owned()).unwrap(),
        );
        assert!(
            !torii_exact_alias_permission_matches_route(&malformed, dataspace, &wrong_domain)
                .unwrap()
        );
    }
}
#[tokio::test]
async fn alias_resolve_endpoint_accepts_exact_domain_without_dataspace_permission() {
    let key_pair = checked_torii_test_ed25519_keypair(
        0x97,
        "derive exact domain endpoint resolution fixture key",
    );
    let authority = AccountId::new(key_pair.public_key().clone());
    let app = crate::tests_runtime_handlers::native_ingress_app_with_world_and_nexus_for_test(
        onboarding_alias_test_world(&authority, &authority),
        recipient_lookup_nexus_for_test(iroha_data_model::nexus::LaneVisibility::Restricted),
    );
    bind_account_alias_for_test(&app, &authority, "payee@hbl.sbp");
    let alias = AccountAlias::from_literal(
        "payee@hbl.sbp",
        &app.state.nexus_snapshot().dataspace_catalog,
    )
    .expect("HBL alias should parse");
    grant_alias_resolve_permissions(&app, &authority, &alias);
    let request = routing::AliasResolveRequestDto {
        alias: "payee@hbl.sbp".to_owned(),
    };
    let body = norito::json::to_vec(&request).expect("encode alias resolve request");
    let method = axum::http::Method::POST;
    let uri: axum::http::Uri = "/v1/aliases/resolve".parse().expect("alias resolve URI");
    let headers = crate::tests_runtime_handlers::signed_network_app_headers(
        app.state.network_id_ref(),
        &authority,
        &key_pair,
        &method,
        &uri,
        &body,
    );
    let response = handler_alias_resolve(
        State(app),
        method,
        uri,
        headers,
        crate::loopback_connect_info(),
        axum::body::Bytes::from(body),
    )
    .await
    .expect("exact domain grant should reach alias resolution")
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .expect("collect alias response")
        .to_bytes();
    let dto: routing::AliasResolveResponseDto =
        norito::json::from_slice(&body).expect("decode alias response");
    assert_eq!(dto.alias, "payee@hbl.sbp");
    assert_eq!(dto.account_id, authority.to_string());
}
#[tokio::test]
async fn alias_reads_resolve_dynamic_only_dataspace_and_preserve_auth_ordering() {
    let key_pair = checked_torii_test_ed25519_keypair(
        0xA0,
        "derive dynamic-only alias read authority fixture key",
    );
    let authority = AccountId::new(key_pair.public_key().clone());
    let app = onboarding_alias_test_app(&authority, &authority);
    let dataspace = DataSpaceId::new(42);
    bind_dynamic_account_alias_for_test(&app, &authority, "merchant@paynet", dataspace);
    let parsed = parse_exact_account_alias_label_with_live_state(&app, "merchant@paynet")
        .expect("dynamic-only dataspace must resolve from active SNS state");
    assert_eq!(parsed.canonical, "merchant@paynet");
    assert_eq!(parsed.label.dataspace, dataspace);
    let by_account = lookup_aliases_by_account_on_chain(
        &app,
        &routing::AliasLookupByAccountRequestDto {
            account_id: authority.to_string(),
            dataspace: Some("paynet".to_owned()),
            domain: None,
        },
    )
    .expect("dynamic alias reverse lookup")
    .expect("account exists");
    assert_eq!(by_account.1.len(), 1);
    assert_eq!(by_account.1[0].alias, "merchant@paynet");
    assert_eq!(by_account.1[0].dataspace, "paynet");
    let indexed = resolve_alias_index_on_chain(&app, 0)
        .expect("dynamic alias index lookup")
        .expect("dynamic alias is indexed");
    assert_eq!(indexed.0, "merchant@paynet");
    assert_eq!(indexed.1, authority);
    let request = routing::AliasResolveRequestDto {
        alias: "merchant@paynet".to_owned(),
    };
    let body = norito::json::to_vec(&request).expect("encode dynamic alias request");
    let method = axum::http::Method::POST;
    let uri: axum::http::Uri = "/v1/aliases/resolve".parse().expect("alias resolve URI");
    let unsigned = handler_alias_resolve(
        State(app.clone()),
        method.clone(),
        uri.clone(),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        axum::body::Bytes::from(body.clone()),
    )
    .await
    .expect_err("a known restricted dynamic dataspace requires authentication");
    assert!(matches!(
        unsigned,
        Error::AppUnauthorized {
            code: "alias_auth_required",
            ..
        }
    ));
    grant_alias_resolve_dataspace_permission(&app, &authority, dataspace);
    let headers = signed_app_headers(&authority, &key_pair, &method, &uri, &body);
    let response = handler_alias_resolve(
        State(app),
        method,
        uri,
        headers,
        crate::loopback_connect_info(),
        axum::body::Bytes::from(body),
    )
    .await
    .expect("authorized dynamic alias resolve")
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
}
#[tokio::test]
async fn account_alias_get_resolves_sns_only_dynamic_dataspace() {
    let key_pair = checked_torii_test_ed25519_keypair(
        0xA2,
        "derive dynamic account alias enumeration authority fixture key",
    );
    let authority = AccountId::new(key_pair.public_key().clone());
    let app = onboarding_alias_test_app(&authority, &authority);
    let dataspace = DataSpaceId::new(42);
    bind_dynamic_account_alias_for_test(&app, &authority, "merchant@paynet", dataspace);
    grant_alias_resolve_dataspace_permission(&app, &authority, dataspace);
    let method = Method::GET;
    let uri: Uri = format!("/v1/accounts/{authority}/aliases")
        .parse()
        .expect("account aliases URI");
    let headers = signed_app_headers(&authority, &key_pair, &method, &uri, &[]);
    let response = handler_account_aliases(
        State(app),
        method,
        uri,
        headers,
        crate::loopback_connect_info(),
        AxPath(authority.to_string()),
    )
    .await
    .expect("SNS-only dynamic alias should enumerate through the account endpoint")
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .expect("collect account alias enumeration response")
        .to_bytes();
    let payload: Value =
        norito::json::from_slice(&body).expect("decode account alias enumeration response");
    assert_eq!(
        payload["account_id"].as_str(),
        Some(authority.to_string().as_str())
    );
    assert_eq!(payload["total"].as_u64(), Some(1));
    assert_eq!(
        payload["items"][0]["alias"].as_str(),
        Some("merchant@paynet")
    );
    assert_eq!(payload["items"][0]["dataspace"].as_str(), Some("paynet"));
}
#[test]
fn alias_read_parser_rejects_static_dynamic_dataspace_collision() {
    let authority =
        checked_torii_test_account_id(0xA1, "derive alias read mapping collision fixture key");
    let app = onboarding_alias_test_app(&authority, &authority);
    bind_dynamic_account_alias_for_test(&app, &authority, "merchant@sbp", DataSpaceId::new(42));
    let error = parse_exact_account_alias_label_with_live_state(&app, "merchant@sbp")
        .expect_err("conflicting static and dynamic dataspace mappings must fail closed");
    assert!(matches!(
        error,
        Error::AppConflict {
            code: iroha_core::sns::ALIAS_CATALOG_MAPPING_CONFLICT_CODE,
            ..
        }
    ));
}
fn install_recipient_lookup_policy_for_test(app: &SharedAppState) {
    let policy_id = app.recipient_lookup.policy_id.clone();
    let account = app
        .state
        .world_view()
        .accounts()
        .iter()
        .next()
        .map(|(id, _)| id.clone())
        .expect("recipient lookup fixture account");
    let policy = FxCorridorPolicy {
        policy_id,
        revision: 1,
        owner: account,
        source_dataspace: recipient_lookup_cbuae_dataspace_for_test(),
        source_asset_definition_id: recipient_lookup_aed_definition_for_test(),
        destination_dataspace: recipient_lookup_sbp_dataspace_for_test(),
        destination_asset_definition_id: AssetDefinitionId::derive_from_components(
            DomainId::try_new("fx", "universal").expect("FX domain"),
            "pkr".parse().expect("PKR name"),
        ),
        allowed_destination_alias_domains: BTreeSet::from([
            DomainId::try_new("hbl", "sbp").expect("HBL domain"),
            DomainId::try_new("ubl", "sbp").expect("UBL domain"),
        ]),
        oracle_feed_id: "recipient_lookup_fx".parse().expect("feed id"),
        max_oracle_age_ms: 60_000,
        max_source_amount_per_settlement: Quantity::from(1_000_u32),
        max_destination_amount_per_settlement: Quantity::from(100_000_u32),
        velocity_window_ms: 60_000,
        max_settlements_per_window: 100,
        max_source_amount_per_window: Quantity::from(10_000_u32),
        max_destination_amount_per_window: Quantity::from(1_000_000_u32),
        enabled: true,
    };
    let mut registry = FxCorridorPolicyRegistry::default();
    registry.upsert(policy);
    let height = next_block_height(app);
    let header = BlockHeader::new(NonZeroU64::new(height).expect("height>0"), None, None, 0, 0);
    let mut block = app.state.block(header);
    block
        .world
        .parameters
        .get_mut()
        .set_parameter(Parameter::Custom(registry.into_custom_parameter()))
        .expect("install the recipient lookup policy fixture");
    block
        .commit_world_overlay_for_testing()
        .expect("commit should persist recipient lookup policy");
    assert_eq!(
        next_block_height(app),
        height,
        "policy fixture setup must not manufacture finalized history"
    );
}
#[tokio::test]
async fn retail_recipient_lookup_rejects_unsigned_public_alias() {
    let authority =
        checked_torii_test_account_id(0x91, "derive recipient lookup public target fixture key");
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
        world_with_account(&authority),
        recipient_lookup_nexus_for_test(iroha_data_model::nexus::LaneVisibility::Public),
    );
    configure_recipient_lookup_sbp_dataspace_for_test(
        &mut app,
        iroha_data_model::nexus::LaneVisibility::Public,
    );
    bind_account_alias_for_test(&app, &authority, "payee@hbl.sbp");
    let body = norito::json::to_vec(&routing::RetailRecipientLookupRequestDto {
        account_id: authority.to_string(),
        alias_fqn: "payee@hbl.sbp".to_owned(),
    })
    .expect("encode request");
    let response = handler_retail_recipient_lookup(
        State(app),
        axum::http::Method::POST,
        "/v1/retail/recipients/lookup"
            .parse()
            .expect("recipient lookup uri"),
        HeaderMap::new(),
        axum::body::Bytes::from(body),
    )
    .await
    .expect("unsigned lookup should return an authentication response")
    .into_response();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-reject-code")
            .and_then(|value| value.to_str().ok()),
        Some("recipient_lookup_signature_required")
    );
    assert_eq!(
        response
            .headers()
            .get(axum::http::header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok()),
        Some("Signature")
    );
}
#[tokio::test]
async fn retail_recipient_lookup_rejects_noncanonical_whitespace() {
    let _guard = app_auth_test_guard(crate::app_auth::CanonicalRequestAuthConfig::default());
    let caller_keypair = checked_torii_test_ed25519_keypair(
        0x92,
        "derive recipient lookup validation caller fixture key",
    );
    let caller = AccountId::new(caller_keypair.public_key().clone());
    let target = checked_torii_test_account_id(
        0x95,
        "derive recipient lookup validation target fixture key",
    );
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
        recipient_lookup_world_for_test(&caller, &target),
        recipient_lookup_nexus_for_test(iroha_data_model::nexus::LaneVisibility::Restricted),
    );
    configure_recipient_lookup_sbp_dataspace_for_test(
        &mut app,
        iroha_data_model::nexus::LaneVisibility::Restricted,
    );
    install_recipient_lookup_policy_for_test(&app);
    let body = norito::json::to_vec(&routing::RetailRecipientLookupRequestDto {
        account_id: format!(" {target}"),
        alias_fqn: "payee@hbl.sbp ".to_owned(),
    })
    .expect("encode request");
    let method = axum::http::Method::POST;
    let uri: axum::http::Uri = "/v1/retail/recipients/lookup"
        .parse()
        .expect("recipient lookup uri");
    let headers = signed_app_headers(&caller, &caller_keypair, &method, &uri, &body);
    let response = handler_retail_recipient_lookup(
        State(app),
        method,
        uri,
        headers,
        axum::body::Bytes::from(body),
    )
    .await
    .expect("noncanonical lookup should return a validation response")
    .into_response();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-reject-code")
            .and_then(|value| value.to_str().ok()),
        Some("invalid_recipient_lookup")
    );
}
#[tokio::test]
async fn retail_recipient_lookup_allows_signed_alias_permission() {
    let _guard = app_auth_test_guard(crate::app_auth::CanonicalRequestAuthConfig::default());
    let caller_keypair = checked_torii_test_ed25519_keypair(
        0x93,
        "derive recipient lookup permission caller fixture key",
    );
    let caller = AccountId::new(caller_keypair.public_key().clone());
    let target = checked_torii_test_account_id(
        0x94,
        "derive recipient lookup permission target fixture key",
    );
    let sbp_dataspace = recipient_lookup_sbp_dataspace_for_test();
    let uaid = UniversalAccountId::from_hash(Hash::new(b"torii::recipient-lookup-auth"));
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
        world_with_target_and_caller_bound_to_dataspace(&target, &caller, uaid, sbp_dataspace),
        recipient_lookup_nexus_for_test(iroha_data_model::nexus::LaneVisibility::Restricted),
    );
    configure_recipient_lookup_sbp_dataspace_for_test(
        &mut app,
        iroha_data_model::nexus::LaneVisibility::Restricted,
    );
    bind_account_alias_for_test(&app, &target, "payee@hbl.sbp");
    let alias = AccountAlias::from_literal(
        "payee@hbl.sbp",
        &app.state.nexus_snapshot().dataspace_catalog,
    )
    .expect("recipient alias should parse");
    grant_alias_resolve_permissions(&app, &caller, &alias);
    let body = norito::json::to_vec(&routing::RetailRecipientLookupRequestDto {
        account_id: target.to_string(),
        alias_fqn: "payee@hbl.sbp".to_owned(),
    })
    .expect("encode request");
    let method = axum::http::Method::POST;
    let uri: axum::http::Uri = "/v1/retail/recipients/lookup"
        .parse()
        .expect("recipient lookup uri");
    let headers = signed_app_headers(&caller, &caller_keypair, &method, &uri, &body);
    let response = handler_retail_recipient_lookup(
        State(app),
        method,
        uri,
        headers,
        axum::body::Bytes::from(body),
    )
    .await
    .expect("permissioned lookup should reach route configuration")
    .into_response();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-reject-code")
            .and_then(|value| value.to_str().ok()),
        Some("recipient_lookup_policy_unavailable")
    );
}
#[tokio::test]
async fn retail_recipient_route_is_corridor_scoped_without_granting_general_alias_access() {
    let _guard = app_auth_test_guard(crate::app_auth::CanonicalRequestAuthConfig::default());
    let caller_keypair = checked_torii_test_ed25519_keypair(
        0x97,
        "derive recipient route funded caller fixture key",
    );
    let caller = AccountId::new(caller_keypair.public_key().clone());
    let target = checked_torii_test_account_id(0x98, "derive recipient route target fixture key");
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
        recipient_lookup_world_for_test(&caller, &target),
        recipient_lookup_nexus_for_test(iroha_data_model::nexus::LaneVisibility::Restricted),
    );
    configure_recipient_lookup_sbp_dataspace_for_test(
        &mut app,
        iroha_data_model::nexus::LaneVisibility::Restricted,
    );
    install_recipient_lookup_policy_for_test(&app);
    bind_account_alias_for_test(&app, &target, "payee@hbl.sbp");
    let corridor_alias = AccountAlias::from_literal(
        "payee@hbl.sbp",
        &app.state.nexus_snapshot().dataspace_catalog,
    )
    .expect("corridor alias");
    assert!(
        !torii_authority_can_resolve_account_alias(
            app.state.view().world(),
            &caller,
            &corridor_alias,
        )
        .unwrap(),
        "the FX caller fixture must not hold general alias-resolution permission",
    );
    let body = norito::json::to_vec(&routing::RetailRecipientRouteRequestDto {
        account_id: target.to_string(),
    })
    .expect("encode route request");
    let method = axum::http::Method::POST;
    let uri: axum::http::Uri = "/v1/retail/recipients/route"
        .parse()
        .expect("recipient route uri");
    let headers = signed_app_headers(&caller, &caller_keypair, &method, &uri, &body);
    let response = handler_retail_recipient_route(
        State(app.clone()),
        method,
        uri,
        headers,
        axum::body::Bytes::from(body),
    )
    .await
    .expect("recipient route should resolve")
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("recipient route body");
    let payload: Value = norito::json::from_slice(&body).expect("recipient route JSON");
    let object = payload.as_object().expect("route response object");
    let target_literal = target.to_string();
    assert_eq!(object.len(), 3);
    assert_eq!(
        object.get("account_id").and_then(Value::as_str),
        Some(target_literal.as_str())
    );
    assert_eq!(
        object.get("alias_fqn").and_then(Value::as_str),
        Some("payee@hbl.sbp")
    );
    assert_eq!(object.get("fi_id").and_then(Value::as_str), Some("hbl.sbp"));
    let generic_body = norito::json::to_vec(&routing::AliasResolveRequestDto {
        alias: "payee@hbl.sbp".to_owned(),
    })
    .expect("encode generic alias request");
    let generic_method = axum::http::Method::POST;
    let generic_uri: axum::http::Uri = "/v1/aliases/resolve"
        .parse()
        .expect("generic alias resolve uri");
    let generic_headers = signed_app_headers(
        &caller,
        &caller_keypair,
        &generic_method,
        &generic_uri,
        &generic_body,
    );
    let generic_response = handler_alias_resolve(
        State(app),
        generic_method,
        generic_uri,
        generic_headers,
        crate::loopback_connect_info(),
        axum::body::Bytes::from(generic_body),
    )
    .await
    .expect("generic alias denial must be a typed response")
    .into_response();
    assert_eq!(generic_response.status(), StatusCode::FORBIDDEN);
}
#[tokio::test]
async fn retail_recipient_route_fails_closed_for_missing_and_ambiguous_bindings() {
    let _guard = app_auth_test_guard(crate::app_auth::CanonicalRequestAuthConfig::default());
    let caller_keypair = checked_torii_test_ed25519_keypair(
        0x99,
        "derive recipient route ambiguity caller fixture key",
    );
    let caller = AccountId::new(caller_keypair.public_key().clone());
    let target =
        checked_torii_test_account_id(0x9a, "derive recipient route ambiguity target fixture key");
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
        recipient_lookup_world_for_test(&caller, &target),
        recipient_lookup_nexus_for_test(iroha_data_model::nexus::LaneVisibility::Restricted),
    );
    configure_recipient_lookup_sbp_dataspace_for_test(
        &mut app,
        iroha_data_model::nexus::LaneVisibility::Restricted,
    );
    install_recipient_lookup_policy_for_test(&app);
    let body = norito::json::to_vec(&routing::RetailRecipientRouteRequestDto {
        account_id: target.to_string(),
    })
    .expect("encode route request");
    let method = axum::http::Method::POST;
    let uri: axum::http::Uri = "/v1/retail/recipients/route"
        .parse()
        .expect("recipient route uri");
    let headers = signed_app_headers(&caller, &caller_keypair, &method, &uri, &body);
    let missing = handler_retail_recipient_route(
        State(app.clone()),
        method.clone(),
        uri.clone(),
        headers,
        axum::body::Bytes::from(body.clone()),
    )
    .await
    .expect("missing route response");
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    bind_account_alias_for_test(&app, &target, "payee@hbl.sbp");
    bind_account_alias_for_test(&app, &target, "payee@ubl.sbp");
    let headers = signed_app_headers(&caller, &caller_keypair, &method, &uri, &body);
    let ambiguous = handler_retail_recipient_route(
        State(app),
        method,
        uri,
        headers,
        axum::body::Bytes::from(body),
    )
    .await
    .expect("ambiguous route response");
    assert_eq!(ambiguous.status(), StatusCode::CONFLICT);
}
#[tokio::test]
async fn fee_sponsor_program_by_id_returns_the_exact_on_chain_program() {
    let _guard = app_auth_test_guard(crate::app_auth::CanonicalRequestAuthConfig::default());
    let sponsor_keypair =
        checked_torii_test_ed25519_keypair(0x9c, "derive fee sponsor program endpoint fixture key");
    let sponsor = AccountId::new(sponsor_keypair.public_key().clone());
    let program_id =
        FeeSponsorProgramId::new(sponsor.clone(), "wallet_fx".parse().expect("program name"));
    let program = FeeSponsorProgram::new(program_id.clone(), program_id.sponsor.clone());
    let app = mk_app_state_for_tests_with_world(world_with_account(&sponsor));
    register_fee_sponsor_program_for_test(&app, program_id.clone());
    let body = norito::json::to_vec(&FeeSponsorProgramByIdRequest::new(&program_id))
        .expect("encode sponsor program request");
    let method = axum::http::Method::POST;
    let uri: axum::http::Uri = "/v1/fee-sponsor-programs/by-id"
        .parse()
        .expect("fee sponsor program uri");
    let headers = signed_app_headers(&sponsor, &sponsor_keypair, &method, &uri, &body);
    let response = handler_fee_sponsor_program_by_id(
        State(app),
        method,
        uri,
        headers,
        axum::body::Bytes::from(body),
    )
    .await
    .expect("on-chain sponsor program lookup")
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("fee sponsor program response body");
    let payload: Value = norito::json::from_slice(&body).expect("program response JSON");
    assert_eq!(
        payload,
        norito::json::to_value(&program).expect("canonical direct program JSON")
    );
    let object = payload.as_object().expect("policy response object");
    assert_eq!(
        object.keys().cloned().collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "id".to_owned(),
            "lifecycle".to_owned(),
            "payout_account".to_owned(),
        ])
    );
    assert!(
        !object.contains_key("program"),
        "response must not use an envelope"
    );
}
#[tokio::test]
async fn fee_quote_returns_exact_routing_observation_and_fixed_point_intent() {
    let _guard = app_auth_test_guard(crate::app_auth::CanonicalRequestAuthConfig::default());
    let caller_keypair =
        checked_torii_test_ed25519_keypair(0x9d, "derive successful fee quote fixture key");
    let caller = AccountId::new(caller_keypair.public_key().clone());
    let app = mk_app_state_for_tests_with_world(world_with_account(&caller));
    let payload = TransactionBuilder::new(
        *app.state.network_id_ref(),
        caller.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([iroha_data_model::isi::Log::new(
        iroha_data_model::Level::INFO,
        "quote fixture".to_owned(),
    )])
    .into_payload()
    .expect("build exact unsigned quote payload");
    let body = norito::json::to_vec(&FeeQuoteRequest {
        payload: payload.clone(),
    })
    .expect("encode exact fee quote request");
    let method = axum::http::Method::POST;
    let uri: axum::http::Uri = "/v1/fees/quote".parse().expect("fee quote uri");
    let headers = signed_app_headers(&caller, &caller_keypair, &method, &uri, &body);
    let response = handler_fee_quote(
        State(app),
        method,
        uri,
        headers,
        axum::body::Bytes::from(body),
    )
    .await
    .expect("successful typed fee quote")
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("fee quote response body");
    let quote: FeeQuoteResponse =
        norito::json::from_slice(&body).expect("decode typed fee quote response");
    assert_eq!(quote.intent, payload.fee_payment);
    assert_eq!(quote.observation.route_dataspace_id, DataSpaceId::UNIVERSAL);
    assert_eq!(quote.observation.next_block_height, 1);
    assert!(quote.components.is_empty());
    assert!(quote.capacities.is_empty());
    assert!(matches!(
        quote.decision,
        FeeQuoteDecision::Accepted {
            debit_source: iroha_data_model::nexus::FeeDebitSource::Account(ref account),
            program_revision: None,
        } if account == &caller
    ));
}
#[tokio::test]
async fn fee_quote_accepts_an_absent_authority_that_self_registers_first() {
    let _guard = app_auth_test_guard(crate::app_auth::CanonicalRequestAuthConfig::default());
    let caller_keypair =
        checked_torii_test_ed25519_keypair(0x9e, "derive self-registering fee quote fixture key");
    let caller = AccountId::new(caller_keypair.public_key().clone());
    let app = mk_app_state_for_tests();
    assert!(
        app.state.world_view().account(&caller).is_err(),
        "self-registering quote authority must start absent"
    );
    let payload = TransactionBuilder::new(
        *app.state.network_id_ref(),
        caller.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([iroha_data_model::isi::Register::account(Account::new(
        caller.clone(),
    ))])
    .into_payload()
    .expect("build self-registering unsigned quote payload");
    let body = norito::json::to_vec(&FeeQuoteRequest {
        payload: payload.clone(),
    })
    .expect("encode self-registering fee quote request");
    let method = axum::http::Method::POST;
    let uri: axum::http::Uri = "/v1/fees/quote".parse().expect("fee quote uri");
    let headers = signed_app_headers(&caller, &caller_keypair, &method, &uri, &body);
    let response = handler_fee_quote(
        State(app),
        method,
        uri,
        headers,
        axum::body::Bytes::from(body),
    )
    .await
    .expect("self-registering fee quote response")
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("self-registering fee quote response body");
    let quote: FeeQuoteResponse =
        norito::json::from_slice(&body).expect("decode self-registering fee quote response");
    assert_eq!(quote.intent, payload.fee_payment);
    assert!(matches!(
        quote.decision,
        FeeQuoteDecision::Accepted {
            debit_source: iroha_data_model::nexus::FeeDebitSource::Account(ref account),
            program_revision: None,
        } if account == &caller
    ));
}
#[tokio::test]
async fn retail_recipient_route_and_sponsor_program_reject_noncanonical_or_malformed_bodies() {
    let caller_keypair =
        checked_torii_test_ed25519_keypair(0x9a, "derive recipient validation caller fixture key");
    let caller = AccountId::new(caller_keypair.public_key().clone());
    let target =
        checked_torii_test_account_id(0x9b, "derive recipient route validation target fixture key");
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
        recipient_lookup_world_for_test(&caller, &target),
        recipient_lookup_nexus_for_test(iroha_data_model::nexus::LaneVisibility::Public),
    );
    configure_recipient_lookup_sbp_dataspace_for_test(
        &mut app,
        iroha_data_model::nexus::LaneVisibility::Public,
    );
    install_recipient_lookup_policy_for_test(&app);
    let whitespace_route = norito::json::to_vec(&routing::RetailRecipientRouteRequestDto {
        account_id: format!(" {target}"),
    })
    .expect("encode whitespace route request");
    let method = axum::http::Method::POST;
    let route_uri: axum::http::Uri = "/v1/retail/recipients/route"
        .parse()
        .expect("recipient route uri");
    let headers = signed_app_headers(
        &caller,
        &caller_keypair,
        &method,
        &route_uri,
        &whitespace_route,
    );
    let response = handler_retail_recipient_route(
        State(app.clone()),
        method.clone(),
        route_uri.clone(),
        headers,
        axum::body::Bytes::from(whitespace_route),
    )
    .await
    .expect("whitespace route response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let malformed_body = br#"{"account_id":"unterminated"#;
    let headers = signed_app_headers(
        &caller,
        &caller_keypair,
        &method,
        &route_uri,
        malformed_body,
    );
    let malformed = handler_retail_recipient_route(
        State(app.clone()),
        method.clone(),
        route_uri.clone(),
        headers,
        axum::body::Bytes::from_static(malformed_body),
    )
    .await
    .expect_err("malformed route JSON must fail")
    .into_response();
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
    for invalid_body in [
        format!(r#"{{"account_id":"{target}","extra":true}}"#).into_bytes(),
        format!(r#"{{"account_id":"{target}","account_id":"{target}"}}"#).into_bytes(),
        br#"[]"#.to_vec(),
    ] {
        let headers =
            signed_app_headers(&caller, &caller_keypair, &method, &route_uri, &invalid_body);
        let response = handler_retail_recipient_route(
            State(app.clone()),
            method.clone(),
            route_uri.clone(),
            headers,
            axum::body::Bytes::from(invalid_body),
        )
        .await
        .map_or_else(IntoResponse::into_response, |response| response);
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    let lookup_uri: axum::http::Uri = "/v1/retail/recipients/lookup"
        .parse()
        .expect("recipient lookup uri");
    for invalid_body in [
        format!(r#"{{"account_id":"{target}","alias_fqn":"payee@hbl.sbp","extra":true}}"#)
            .into_bytes(),
        format!(
            r#"{{"account_id":"{target}","alias_fqn":"payee@hbl.sbp","alias_fqn":"payee@hbl.sbp"}}"#
        )
        .into_bytes(),
        br#"[]"#.to_vec(),
    ] {
        let headers = signed_app_headers(
            &caller,
            &caller_keypair,
            &method,
            &lookup_uri,
            &invalid_body,
        );
        let response = handler_retail_recipient_lookup(
            State(app.clone()),
            method.clone(),
            lookup_uri.clone(),
            headers,
            axum::body::Bytes::from(invalid_body),
        )
        .await
        .map_or_else(IntoResponse::into_response, |response| response);
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    let program_id =
        FeeSponsorProgramId::new(target.clone(), "wallet_fx".parse().expect("program name"));
    let whitespace_sponsor = norito::json::to_vec(&FeeSponsorProgramByIdRequest {
        program_id: format!("{program_id} "),
    })
    .expect("encode whitespace sponsor program request");
    let sponsor_uri: axum::http::Uri = "/v1/fee-sponsor-programs/by-id"
        .parse()
        .expect("fee sponsor program uri");
    let headers = signed_app_headers(
        &caller,
        &caller_keypair,
        &method,
        &sponsor_uri,
        &whitespace_sponsor,
    );
    let response = handler_fee_sponsor_program_by_id(
        State(app.clone()),
        method.clone(),
        sponsor_uri.clone(),
        headers,
        axum::body::Bytes::from(whitespace_sponsor),
    )
    .await
    .expect("whitespace sponsor response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let malformed_body = br#"{"program_id":"#;
    let headers = signed_app_headers(
        &caller,
        &caller_keypair,
        &method,
        &sponsor_uri,
        malformed_body,
    );
    let malformed = handler_fee_sponsor_program_by_id(
        State(app.clone()),
        method.clone(),
        sponsor_uri.clone(),
        headers,
        axum::body::Bytes::from_static(malformed_body),
    )
    .await
    .expect_err("malformed sponsor JSON must fail")
    .into_response();
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
    for invalid_body in [
        format!(r#"{{"program_id":"{program_id}","extra":true}}"#).into_bytes(),
        format!(r#"{{"program_id":"{program_id}","program_id":"{program_id}"}}"#).into_bytes(),
        br#"[]"#.to_vec(),
    ] {
        let headers = signed_app_headers(
            &caller,
            &caller_keypair,
            &method,
            &sponsor_uri,
            &invalid_body,
        );
        let response = handler_fee_sponsor_program_by_id(
            State(app.clone()),
            method.clone(),
            sponsor_uri.clone(),
            headers,
            axum::body::Bytes::from(invalid_body),
        )
        .await
        .map_or_else(IntoResponse::into_response, |response| response);
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    let quote_uri: axum::http::Uri = "/v1/fees/quote".parse().expect("fee quote uri");
    let malformed_quote = br#"{"payload":"#;
    let headers = signed_app_headers(
        &caller,
        &caller_keypair,
        &method,
        &quote_uri,
        malformed_quote,
    );
    let response = handler_fee_quote(
        State(app),
        method,
        quote_uri,
        headers,
        axum::body::Bytes::from_static(malformed_quote),
    )
    .await
    .expect("malformed signed fee quote rejection")
    .into_response();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .unwrap(),
        "application/x-norito"
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("fee quote rejection body");
    let envelope: ErrorEnvelope =
        norito::decode_from_bytes(&body).expect("typed Norito fee quote error envelope");
    let fee = envelope
        .details
        .and_then(|details| details.fee)
        .expect("stable fee rejection details");
    assert_eq!(fee.code, FeeRejectionCode::InvalidFeeIntent.as_str());
    assert!(!fee.retryable);
}
#[test]
fn alias_setup_parent_and_size_diagnostics_are_deterministic() {
    use iroha_data_model::alias_setup::{
        AccountAliasName, AliasSetupSeverityV1, AliasTargetV1, ResolvedAccountAliasV1,
        ResolvedDataSpaceV1, ResolvedDomainV1,
    };
    let dataspace = ResolvedDataSpaceV1::new(
        "paynet".parse().expect("canonical dataspace name"),
        DataSpaceId::new(7),
    );
    let domain = ResolvedDomainV1::new(
        DomainId::parse_fully_qualified("banka.paynet").expect("canonical domain"),
        DataSpaceId::new(7),
    );
    let alias = ResolvedAccountAliasV1::new(
        "merchant@banka.paynet"
            .parse::<AccountAliasName>()
            .expect("canonical account alias"),
        DataSpaceId::new(7),
    );
    let dataspace_target = AliasTargetV1::Dataspace(dataspace.clone());
    let domain_target = AliasTargetV1::Domain(domain.clone());
    let alias_target = AliasTargetV1::AccountAlias(alias);
    assert_eq!(alias_setup_parent_target(&dataspace_target), None);
    assert_eq!(
        alias_setup_parent_target(&domain_target),
        Some(dataspace_target.clone())
    );
    assert_eq!(
        alias_setup_parent_target(&alias_target),
        Some(domain_target.clone())
    );
    assert!(alias_setup_parent_expiry_warning(&domain_target, &dataspace_target, 20, 20).is_none());
    let warning = alias_setup_parent_expiry_warning(&domain_target, &dataspace_target, 21, 20)
        .expect("shorter parent lease warning");
    assert_eq!(warning.code, "alias.plan.parent_lease_expires_first");
    assert_eq!(warning.severity, AliasSetupSeverityV1::Warning);
    assert!(alias_setup_transaction_size_blocker(64, 64).is_none());
    let blocker = alias_setup_transaction_size_blocker(65, 64).expect("oversized payload blocker");
    assert_eq!(blocker.code, "alias.plan.transaction_oversized");
    assert_eq!(blocker.severity, AliasSetupSeverityV1::Error);
    let request_time = UNIX_EPOCH + Duration::from_millis(1_000);
    assert_eq!(alias_plan_deadline(request_time, None).unwrap(), 61_000);
    assert_eq!(
        alias_plan_deadline(request_time, Some(30_000)).unwrap(),
        30_000
    );
    assert_eq!(alias_plan_deadline(request_time, Some(999)).unwrap(), 999);
    assert!(alias_plan_deadline(UNIX_EPOCH - Duration::from_millis(1), None).is_err());
}
#[tokio::test]
async fn alias_setup_plan_after_idle_keeps_ledger_quote_and_fresh_request_deadline() {
    use iroha_data_model::{
        alias_setup::{
            AccountAliasRoleV1, AccountProvisionV1, AliasAccountIntentV1, AliasIntentV1,
            AliasLeaseAcquisitionV1, AliasQuoteGuardV1, AliasSetupPlanRequestV1,
            AliasTransactionPlanV1, ResolvedAccountAliasV1,
        },
        isi::alias_setup::EnsureAlias,
    };

    let key_pair = checked_torii_test_ed25519_keypair(0xA8, "derive idle alias planner authority");
    let authority = AccountId::new(key_pair.public_key().clone());
    let app = onboarding_alias_test_app(&authority, &authority);
    let ledger_time_ms = 1_000;
    record_latest_committed_header_for_test(&app, 1, ledger_time_ms);
    let alias = ResolvedAccountAliasV1::new(
        "payee@hbl.sbp".parse().expect("canonical alias"),
        recipient_lookup_sbp_dataspace_for_test(),
    );
    let (anchor_hash, policy, expected_quote) = {
        let view = app.state.view();
        let policy = iroha_core::sns::policy_by_id(
            view.world(),
            iroha_data_model::sns::ACCOUNT_ALIAS_SUFFIX_ID,
        )
        .expect("read fixture policy")
        .expect("installed fixture policy");
        let quote = iroha_core::sns::quote_account_alias_registration(
            view.world(),
            &view.nexus().dataspace_catalog,
            &alias.account_alias(),
            &authority,
            1,
            None,
            ledger_time_ms,
        )
        .expect("quote against the actual committed ledger time");
        (Hash::from(view.latest_block_hash().unwrap()), policy, quote)
    };
    let before_ms = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .expect("current time fits u64");
    assert!(before_ms > ledger_time_ms + ALIAS_PLAN_TTL_MS);
    for guard_deadline_ms in [before_ms + 2 * ALIAS_PLAN_TTL_MS, before_ms + 30_000] {
        let request = AliasSetupPlanRequestV1::new(vec![EnsureAlias::new(
            AliasIntentV1::AccountAlias(AliasAccountIntentV1 {
                alias: alias.clone(),
                target_account: authority.clone(),
                provision: AccountProvisionV1::Existing,
                role: AccountAliasRoleV1::Primary,
            }),
            AliasLeaseAcquisitionV1::new(1, None),
            AliasQuoteGuardV1 {
                expected_policy_version: policy.policy_version,
                expected_payment_asset: expected_quote.payment_asset_definition_id.clone(),
                max_amount: expected_quote.charge_amount.clone(),
                valid_until_ms: guard_deadline_ms,
            },
        )]);
        let body = norito::json::to_vec(&request).expect("encode setup request");
        let method = Method::POST;
        let uri = "/v1/aliases/setup/plan".parse().expect("setup URI");
        let headers = signed_app_headers(&authority, &key_pair, &method, &uri, &body);
        let response = handler_alias_setup_plan(
            State(app.clone()),
            method,
            uri,
            headers,
            crate::loopback_connect_info(),
            body.into(),
        )
        .await
        .expect("signed setup planner response");
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 65_536)
            .await
            .unwrap();
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let plan: AliasTransactionPlanV1 = norito::json::from_slice(&body).expect("setup plan");
        let after_ms = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .expect("current time fits u64");
        assert!(
            plan.body.valid_until_ms >= after_ms,
            "new plan must pass SDK wall-clock expiry"
        );
        assert!(plan.body.valid_until_ms >= (before_ms + ALIAS_PLAN_TTL_MS).min(guard_deadline_ms));
        assert!(plan.body.valid_until_ms <= (after_ms + ALIAS_PLAN_TTL_MS).min(guard_deadline_ms));
        assert_eq!(plan.body.anchor.block_height, 1);
        assert_eq!(plan.body.anchor.block_hash, anchor_hash);
        let quote = plan.body.resources[0]
            .quote
            .as_ref()
            .expect("creation lease quote");
        assert_eq!(quote.exact_amount, expected_quote.charge_amount);
        assert_eq!(quote.expires_at_ms, expected_quote.expires_at_ms);
        assert_eq!(
            quote.grace_expires_at_ms,
            expected_quote.grace_expires_at_ms
        );
        assert_eq!(
            quote.redemption_expires_at_ms,
            expected_quote.redemption_expires_at_ms
        );
        assert_eq!(quote.guard.valid_until_ms, guard_deadline_ms);
        iroha::client::decode_and_verify_alias_setup_plan_for_request(&request, &plan)
            .expect("native SDK accepts the exact unchanged request and frames");
    }
    assert_eq!(
        app.state
            .view()
            .latest_block()
            .expect("funded canonical history read")
            .unwrap()
            .header()
            .creation_time()
            .as_millis(),
        u128::from(ledger_time_ms)
    );
}

#[tokio::test]
async fn alias_auto_renew_plan_after_idle_keeps_anchor_and_fresh_request_deadline() {
    use iroha_data_model::{
        alias_setup::{
            AliasAutoRenewPlanRequestV1, AliasLifecycleTransactionPlanV1, AliasTargetV1,
            ResolvedAccountAliasV1,
        },
        isi::alias_setup::ConfigureAliasAutoRenew,
    };
    let key_pair = checked_torii_test_ed25519_keypair(0xA9, "derive idle auto-renew authority");
    let authority = AccountId::new(key_pair.public_key().clone());
    let app = onboarding_alias_test_app(&authority, &authority);
    bind_account_alias_for_test(&app, &authority, "payee@hbl.sbp");
    record_latest_committed_header_for_test(&app, 1, 1_000);
    let anchor_hash = Hash::from(app.state.view().latest_block_hash().unwrap());
    let request = AliasAutoRenewPlanRequestV1::new(ConfigureAliasAutoRenew::new(
        AliasTargetV1::AccountAlias(ResolvedAccountAliasV1::new(
            "payee@hbl.sbp".parse().expect("canonical alias"),
            recipient_lookup_sbp_dataspace_for_test(),
        )),
        0,
        None,
    ));
    let body = norito::json::to_vec(&request).expect("encode auto-renew request");
    let method = Method::POST;
    let uri = "/v1/aliases/auto-renew/plan"
        .parse()
        .expect("auto-renew URI");
    let headers = signed_app_headers(&authority, &key_pair, &method, &uri, &body);
    let before_ms = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    let response = handler_alias_auto_renew_plan(
        State(app.clone()),
        method,
        uri,
        headers,
        crate::loopback_connect_info(),
        body.into(),
    )
    .await
    .expect("signed auto-renew planner response");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 65_536)
        .await
        .unwrap();
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let plan: AliasLifecycleTransactionPlanV1 =
        norito::json::from_slice(&body).expect("auto-renew plan");
    let after_ms = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    assert!(
        plan.body.valid_until_ms >= after_ms,
        "new plan must pass SDK wall-clock expiry"
    );
    assert!(plan.body.valid_until_ms >= before_ms + ALIAS_PLAN_TTL_MS);
    assert!(plan.body.valid_until_ms <= after_ms + ALIAS_PLAN_TTL_MS);
    assert_eq!(plan.body.anchor.block_height, 1);
    assert_eq!(plan.body.anchor.block_hash, anchor_hash);
    assert!(
        iroha::client::decode_and_verify_alias_auto_renew_plan_for_request(&request, &plan)
            .expect("native SDK verifies exact no-op plan")
            .is_none()
    );
    assert_eq!(
        app.state
            .view()
            .latest_block()
            .expect("funded canonical history read")
            .unwrap()
            .header()
            .creation_time()
            .as_millis(),
        1_000
    );
}
#[tokio::test]
async fn alias_planner_and_recipient_reads_authenticate_before_parsing() {
    let app = mk_app_state_for_tests();
    let method = axum::http::Method::POST;
    macro_rules! assert_alias_auth_first {
        ($handler:ident, $path:literal, with_connect_info) => {{
            let error = $handler(
                State(app.clone()),
                method.clone(),
                $path.parse().expect("protected alias route uri"),
                HeaderMap::new(),
                axum::extract::ConnectInfo("127.0.0.1:19452".parse().expect("socket address")),
                axum::body::Bytes::from_static(b"{"),
            )
            .await
            .expect_err("unsigned malformed alias request must fail authentication first");
            assert!(matches!(
                &error,
                Error::AppUnauthorized {
                    code: "alias_auth_required",
                    ..
                }
            ));
            let response = error.into_response();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(
                response
                    .headers()
                    .get("x-iroha-reject-code")
                    .and_then(|value| value.to_str().ok()),
                Some("alias_auth_required")
            );
            assert_eq!(
                response
                    .headers()
                    .get(axum::http::header::WWW_AUTHENTICATE)
                    .and_then(|value| value.to_str().ok()),
                Some("Signature")
            );
        }};
    }
    assert_alias_auth_first!(
        handler_alias_setup_plan,
        "/v1/aliases/setup/plan",
        with_connect_info
    );
    assert_alias_auth_first!(
        handler_alias_lease_renew_plan,
        "/v1/aliases/lease/renew/plan",
        with_connect_info
    );
    assert_alias_auth_first!(
        handler_alias_auto_renew_plan,
        "/v1/aliases/auto-renew/plan",
        with_connect_info
    );
    let unsigned_resolve = handler_alias_resolve(
        State(app.clone()),
        method.clone(),
        "/v1/aliases/resolve".parse().expect("alias resolve uri"),
        HeaderMap::new(),
        axum::extract::ConnectInfo("127.0.0.1:19452".parse().expect("socket address")),
        axum::body::Bytes::from_static(b"{"),
    )
    .await
    .expect_err("malformed unsigned public lookup must fail parsing")
    .into_response();
    assert_eq!(unsigned_resolve.status(), StatusCode::BAD_REQUEST);
    let index_error = handler_alias_resolve_index(
        State(app.clone()),
        method.clone(),
        "/v1/aliases/resolve-index"
            .parse()
            .expect("alias index uri"),
        HeaderMap::new(),
        axum::body::Bytes::from_static(b"{"),
    )
    .await
    .expect_err("unsigned index enumeration must authenticate before parsing");

    assert!(matches!(
        &index_error,
        Error::AppUnauthorized {
            code: "alias_auth_required",
            ..
        }
    ));
    assert_eq!(
        index_error.into_response().status(),
        StatusCode::UNAUTHORIZED
    );
    let reverse_response = handler_alias_lookup_by_account(
        State(app.clone()),
        method.clone(),
        "/v1/aliases/by-account".parse().expect("alias account uri"),
        HeaderMap::new(),
        axum::body::Bytes::from_static(b"{"),
    )
    .await
    .expect_err("malformed unsigned reverse lookup must fail parsing")
    .into_response();
    assert_eq!(reverse_response.status(), StatusCode::BAD_REQUEST);
    let route = handler_retail_recipient_route(
        State(app.clone()),
        method.clone(),
        "/v1/retail/recipients/route"
            .parse()
            .expect("recipient route uri"),
        HeaderMap::new(),
        axum::body::Bytes::from_static(b"{"),
    )
    .await
    .expect("unsigned recipient route rejection");
    assert_eq!(route.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        route
            .headers()
            .get("x-iroha-reject-code")
            .and_then(|value| value.to_str().ok()),
        Some("recipient_lookup_signature_required")
    );
    assert_eq!(
        route
            .headers()
            .get(axum::http::header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok()),
        Some("Signature")
    );
    let lookup = handler_retail_recipient_lookup(
        State(app.clone()),
        method.clone(),
        "/v1/retail/recipients/lookup"
            .parse()
            .expect("recipient lookup uri"),
        HeaderMap::new(),
        axum::body::Bytes::from_static(b"{"),
    )
    .await
    .expect("unsigned recipient lookup rejection");
    assert_eq!(lookup.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        lookup
            .headers()
            .get("x-iroha-reject-code")
            .and_then(|value| value.to_str().ok()),
        Some("recipient_lookup_signature_required")
    );
    assert_eq!(
        lookup
            .headers()
            .get(axum::http::header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok()),
        Some("Signature")
    );
    let sponsor = handler_fee_sponsor_program_by_id(
        State(app.clone()),
        method.clone(),
        "/v1/fee-sponsor-programs/by-id"
            .parse()
            .expect("fee sponsor program uri"),
        HeaderMap::new(),
        axum::body::Bytes::from_static(b"{"),
    )
    .await
    .expect("unsigned fee sponsor program rejection");
    assert_eq!(sponsor.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        sponsor
            .headers()
            .get("x-iroha-reject-code")
            .and_then(|value| value.to_str().ok()),
        Some("fee_sponsor_program_signature_required")
    );
    assert_eq!(
        sponsor
            .headers()
            .get(axum::http::header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok()),
        Some("Signature")
    );
    let quote = handler_fee_quote(
        State(app),
        method,
        "/v1/fees/quote".parse().expect("fee quote uri"),
        HeaderMap::new(),
        axum::body::Bytes::from_static(b"{"),
    )
    .await
    .expect("unsigned fee quote rejection");
    assert_eq!(quote.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        quote
            .headers()
            .get("x-iroha-reject-code")
            .and_then(|value| value.to_str().ok()),
        Some("fee_quote_signature_required")
    );
    assert_eq!(
        quote
            .headers()
            .get(axum::http::header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok()),
        Some("Signature")
    );
}
#[tokio::test]
async fn retail_recipient_lookup_preserves_requested_account_literal_for_bank_lookup() {
    const PK2_RECIPIENT_LOOKUP_ACCOUNT: &str =
        "sorauﾛ1Nﾅ9XﾂﾜｶPTCﾈﾜ1ﾌｲ3wF4ZxnjAeEﾆｷgYN1ｶﾕｷkAﾔﾋUWP59S";
    const PK2_RECIPIENT_LOOKUP_ALIAS: &str = "bright-brook-5859@ubl.sbp";
    let target = AccountId::parse_encoded(PK2_RECIPIENT_LOOKUP_ACCOUNT)
        .expect("pk2 recipient account fixture must parse");
    let caller_keypair = checked_torii_test_ed25519_keypair(
        0x96,
        "derive recipient lookup funded caller fixture key",
    );
    let caller = AccountId::new(caller_keypair.public_key().clone());
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
        recipient_lookup_world_for_test(&caller, &target),
        recipient_lookup_nexus_for_test(iroha_data_model::nexus::LaneVisibility::Public),
    );
    configure_recipient_lookup_sbp_dataspace_for_test(
        &mut app,
        iroha_data_model::nexus::LaneVisibility::Public,
    );
    install_recipient_lookup_policy_for_test(&app);
    bind_account_alias_for_test(&app, &target, PK2_RECIPIENT_LOOKUP_ALIAS);
    let captured = Arc::new(std::sync::Mutex::new(
        Vec::<(String, String, String, String)>::new(),
    ));
    let captured_for_route = Arc::clone(&captured);
    let response_account_id = PK2_RECIPIENT_LOOKUP_ACCOUNT.to_owned();
    let response_alias = PK2_RECIPIENT_LOOKUP_ALIAS.to_owned();
    let upstream = axum::Router::new().route(
        "/v1/retail/recipients/lookup",
        axum::routing::post(move |headers: HeaderMap, body: Bytes| {
            let captured = Arc::clone(&captured_for_route);
            let response_account_id = response_account_id.clone();
            let response_alias = response_alias.clone();
            async move {
                let request: routing::RetailRecipientLookupRequestDto =
                    norito::json::from_slice(body.as_ref())
                        .expect("recipient lookup upstream request");
                let authorization = headers
                    .get("authorization")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default()
                    .to_owned();
                let request_id = headers
                    .get("x-request-id")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default()
                    .to_owned();
                captured.lock().expect("capture lock").push((
                    request.account_id,
                    request.alias_fqn,
                    authorization,
                    request_id,
                ));
                let body = norito::json::to_vec(&recipient_lookup_response(
                    true,
                    response_account_id,
                    response_alias,
                    "ubl.sbp".to_owned(),
                    Some("Ayesha Khan".to_owned()),
                ))
                .expect("recipient lookup response body");
                Response::builder()
                    .status(StatusCode::OK)
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .expect("upstream response")
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind recipient lookup upstream");
    let addr = listener
        .local_addr()
        .expect("recipient lookup upstream addr");
    let upstream_task = tokio::spawn(async move {
        axum::serve(listener, upstream.into_make_service())
            .await
            .expect("serve recipient lookup upstream");
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    Arc::get_mut(&mut app)
        .expect("unique app state")
        .recipient_lookup = Arc::new(actual::ToriiRecipientLookup {
        policy_id: "cbuae_aed_sbp_pkr".parse().expect("policy id"),
        requests_per_minute: 30,
        request_timeout: Duration::from_secs(2),
        routes: vec![actual::ToriiRecipientLookupRoute {
            fi_id: "ubl.sbp".to_owned(),
            base_url: format!("http://{addr}")
                .parse()
                .expect("recipient lookup upstream url"),
            bearer_token: "lookup-service-token".to_owned(),
        }],
    });
    let body = norito::json::to_vec(&routing::RetailRecipientLookupRequestDto {
        account_id: PK2_RECIPIENT_LOOKUP_ACCOUNT.to_owned(),
        alias_fqn: PK2_RECIPIENT_LOOKUP_ALIAS.to_owned(),
    })
    .expect("encode request");
    let method = axum::http::Method::POST;
    let uri: axum::http::Uri = "/v1/retail/recipients/lookup"
        .parse()
        .expect("recipient lookup uri");
    let headers = signed_app_headers(&caller, &caller_keypair, &method, &uri, &body);
    let response = handler_retail_recipient_lookup(
        State(app),
        method,
        uri,
        headers,
        axum::body::Bytes::from(body),
    )
    .await
    .expect("recipient lookup should execute")
    .into_response();
    upstream_task.abort();
    assert_eq!(response.status(), StatusCode::OK);
    let response_body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("recipient lookup response body");
    let payload: Value =
        norito::json::from_slice(response_body.as_ref()).expect("recipient lookup json");
    assert_eq!(payload["resolved"], Value::Bool(true));
    assert_eq!(
        payload["account_id"].as_str(),
        Some(PK2_RECIPIENT_LOOKUP_ACCOUNT)
    );
    assert_eq!(
        payload["alias_fqn"].as_str(),
        Some(PK2_RECIPIENT_LOOKUP_ALIAS)
    );
    assert_eq!(payload["fi_id"].as_str(), Some("ubl.sbp"));
    assert_eq!(payload["full_name"].as_str(), Some("Ayesha Khan"));
    let captured = captured.lock().expect("capture lock");
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].0, PK2_RECIPIENT_LOOKUP_ACCOUNT);
    assert_eq!(captured[0].1, PK2_RECIPIENT_LOOKUP_ALIAS);
    assert_eq!(captured[0].2, "Bearer lookup-service-token");
    assert!(
        captured[0].3.starts_with("torii-recipient-lookup-"),
        "Torii must send an upstream request ID for Core API audit"
    );
}
#[test]
fn recipient_lookup_account_identity_confirmation_requires_exact_canonical_literal() {
    let account_id =
        checked_torii_test_account_id(0x95, "derive recipient lookup identity match fixture key");
    let literal = account_id
        .canonical_i105()
        .expect("recipient lookup account fixture i105");
    assert!(recipient_lookup_account_identity_matches(
        Some(&literal),
        &account_id,
    ));
    assert!(!recipient_lookup_account_identity_matches(
        Some("not-an-account"),
        &account_id,
    ));
    assert!(!recipient_lookup_account_identity_matches(
        Some(&format!(" {literal}")),
        &account_id,
    ));
    assert!(!recipient_lookup_account_identity_matches(
        None,
        &account_id
    ));
}
#[test]
fn recipient_lookup_upstream_request_id_forwards_valid_header_or_generates_private_id() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-request-id",
        HeaderValue::from_static("client-request-123"),
    );
    assert_eq!(
        recipient_lookup_upstream_request_id(&headers, b"lookup-body"),
        "client-request-123"
    );
    headers.insert("x-request-id", HeaderValue::from_static("   "));
    let generated = recipient_lookup_upstream_request_id(&headers, b"lookup-body");
    assert!(generated.starts_with("torii-recipient-lookup-"));
    assert!(!generated.contains("lookup-body"));
}
#[tokio::test]
async fn alias_resolve_rejects_unsigned_request() {
    let authority =
        checked_torii_test_account_id(0x84, "derive alias resolve unsigned authority fixture key");
    // Exact public mappings permit unsigned reads; a restricted mapping must
    // require the signed caller before consulting its original alias state.
    let app = crate::tests_runtime_handlers::native_ingress_app_with_world_and_nexus_for_test(
        world_with_account(&authority),
        crate::tests_runtime_handlers::private_ingress_nexus_for_test(),
    );
    bind_account_alias_for_test(&app, &authority, "public@universal");
    let public_body = norito::json::to_vec(&routing::AliasResolveRequestDto {
        alias: "public@universal".to_owned(),
    })
    .unwrap();
    let public = handler_alias_resolve(
        State(app.clone()),
        Method::POST,
        "/v1/aliases/resolve".parse().unwrap(),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        axum::body::Bytes::from(public_body),
    )
    .await
    .expect("exact public mapping permits unsigned reads")
    .into_response();
    assert_eq!(public.status(), StatusCode::OK);
    let public_bytes = axum::body::to_bytes(public.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let public_dto: routing::AliasResolveResponseDto =
        norito::json::from_slice(&public_bytes).unwrap();
    assert_eq!(public_dto.alias, "public@universal");
    assert_eq!(public_dto.account_id, authority.to_string());
    let request = routing::AliasResolveRequestDto {
        alias: "banking@centralbank.restricted".to_string(),
    };
    let body = norito::json::to_vec(&request).expect("encode request");
    let error = handler_alias_resolve(
        State(app),
        axum::http::Method::POST,
        "/v1/aliases/resolve".parse().expect("alias resolve uri"),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        axum::body::Bytes::from(body),
    )
    .await
    .expect_err("unsigned exact alias resolution must fail closed");
    assert!(matches!(
        &error,
        Error::AppUnauthorized {
            code: "alias_auth_required",
            ..
        }
    ));
    let response = error.into_response();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-reject-code")
            .and_then(|value| value.to_str().ok()),
        Some("alias_auth_required")
    );
}
#[tokio::test]
async fn contract_alias_reads_reject_unsigned_requests_before_parsing() {
    let app = mk_app_state_for_tests();
    let method = axum::http::Method::POST;
    let alias_uri: axum::http::Uri = "/v1/contracts/aliases/resolve"
        .parse()
        .expect("contract alias resolve URI");
    let alias_error = handler_contract_alias_resolve(
        State(app),
        method,
        alias_uri,
        HeaderMap::new(),
        crate::loopback_connect_info(),
        axum::body::Bytes::from_static(b"{"),
    )
    .await
    .expect_err("unsigned malformed contract alias request must fail authentication first");
    assert!(matches!(
        alias_error,
        Error::AppUnauthorized {
            code: "alias_auth_required",
            ..
        }
    ));
}
#[tokio::test]
async fn public_exact_alias_reads_reject_bad_supplied_signatures() {
    let authority_keypair = checked_torii_test_ed25519_keypair(
        0x85,
        "derive public exact alias bad-signature fixture key",
    );
    let authority = AccountId::new(authority_keypair.public_key().clone());
    let app = mk_app_state_for_tests_with_world(world_with_account(&authority));
    let resolve_body = norito::json::to_vec(&routing::AliasResolveRequestDto {
        alias: "missing@universal".to_owned(),
    })
    .expect("encode resolve request");
    let method = axum::http::Method::POST;
    let resolve_uri: axum::http::Uri = "/v1/aliases/resolve".parse().expect("alias resolve uri");
    let mut resolve_headers = signed_app_headers(
        &authority,
        &authority_keypair,
        &method,
        &resolve_uri,
        &resolve_body,
    );
    resolve_headers.insert(HEADER_SIGNATURE, HeaderValue::from_static("00"));
    handler_alias_resolve(
        State(app.clone()),
        method.clone(),
        resolve_uri,
        resolve_headers,
        crate::loopback_connect_info(),
        axum::body::Bytes::from(resolve_body),
    )
    .await
    .expect_err("invalid supplied signatures must not downgrade to anonymous resolve");
    let lookup_body = norito::json::to_vec(&routing::AliasLookupByAccountRequestDto {
        account_id: authority.to_string(),
        dataspace: None,
        domain: None,
    })
    .expect("encode reverse lookup request");
    let lookup_uri: axum::http::Uri = "/v1/aliases/by-account"
        .parse()
        .expect("alias by-account uri");
    let mut lookup_headers = signed_app_headers(
        &authority,
        &authority_keypair,
        &method,
        &lookup_uri,
        &lookup_body,
    );
    lookup_headers.insert(HEADER_SIGNATURE, HeaderValue::from_static("00"));
    handler_alias_lookup_by_account(
        State(app),
        method,
        lookup_uri,
        lookup_headers,
        axum::body::Bytes::from(lookup_body),
    )
    .await
    .expect_err("invalid supplied signatures must not downgrade to anonymous reverse lookup");
}
#[tokio::test]
async fn public_exact_alias_reads_use_independent_route_rate_limits() {
    let authority_keypair = checked_torii_test_ed25519_keypair(
        0x86,
        "derive public exact alias rate-limit fixture key",
    );
    let authority = AccountId::new(authority_keypair.public_key().clone());
    let mut app = crate::tests_runtime_handlers::native_ingress_app_with_world_for_test(
        world_with_account(&authority),
    );
    bind_account_alias_for_test(&app, &authority, "banking@universal");
    let alias_label = AccountAlias::new(
        "banking".parse().expect("label"),
        None,
        DataSpaceId::UNIVERSAL,
    );
    grant_alias_resolve_permissions(&app, &authority, &alias_label);
    Arc::get_mut(&mut app)
        .expect("unique app state")
        .rate_limiter = limits::RateLimiter::new(Some(1), Some(1));
    let connect_info = crate::loopback_connect_info();
    let resolve_body = norito::json::to_vec(&routing::AliasResolveRequestDto {
        alias: "banking@universal".to_owned(),
    })
    .expect("encode resolve request");
    let resolve_uri: axum::http::Uri = "/v1/aliases/resolve".parse().expect("alias resolve uri");
    let first_resolve_headers = crate::tests_runtime_handlers::signed_network_app_headers(
        app.state.network_id_ref(),
        &authority,
        &authority_keypair,
        &axum::http::Method::POST,
        &resolve_uri,
        &resolve_body,
    );
    let first = handler_alias_resolve(
        State(app.clone()),
        axum::http::Method::POST,
        resolve_uri.clone(),
        first_resolve_headers,
        connect_info,
        axum::body::Bytes::from(resolve_body.clone()),
    )
    .await
    .expect("first exact resolve should be admitted")
    .into_response();
    assert_eq!(first.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(first.into_body())
        .await
        .unwrap()
        .to_bytes();
    let resolved: norito::json::Value = norito::json::from_slice(&body).unwrap();
    assert_eq!(resolved["alias"].as_str(), Some("banking@universal"));
    assert_eq!(
        resolved["account_id"].as_str(),
        Some(authority.to_string().as_str())
    );
    let second_resolve_headers = crate::tests_runtime_handlers::signed_network_app_headers(
        app.state.network_id_ref(),
        &authority,
        &authority_keypair,
        &axum::http::Method::POST,
        &resolve_uri,
        &resolve_body,
    );
    let throttled = handler_alias_resolve(
        State(app.clone()),
        axum::http::Method::POST,
        resolve_uri,
        second_resolve_headers,
        crate::loopback_connect_info(),
        axum::body::Bytes::from(resolve_body),
    )
    .await
    .expect_err("second exact resolve should exhaust its route bucket")
    .into_response();
    assert_eq!(throttled.status(), StatusCode::TOO_MANY_REQUESTS);
    let lookup_body = norito::json::to_vec(&routing::AliasLookupByAccountRequestDto {
        account_id: authority.to_string(),
        dataspace: None,
        domain: None,
    })
    .expect("encode reverse lookup request");
    let lookup_uri: axum::http::Uri = "/v1/aliases/by-account"
        .parse()
        .expect("alias by-account uri");
    let lookup_headers = crate::tests_runtime_handlers::signed_network_app_headers(
        app.state.network_id_ref(),
        &authority,
        &authority_keypair,
        &axum::http::Method::POST,
        &lookup_uri,
        &lookup_body,
    );
    let lookup = handler_public_alias_lookup_by_account(
        State(app),
        axum::http::Method::POST,
        lookup_uri,
        lookup_headers,
        crate::loopback_connect_info(),
        axum::body::Bytes::from(lookup_body),
    )
    .await
    .expect("reverse lookup must use an independent route bucket")
    .into_response();
    assert_eq!(lookup.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(lookup.into_body())
        .await
        .unwrap()
        .to_bytes();
    let aliases: norito::json::Value = norito::json::from_slice(&body).unwrap();
    assert_eq!(
        aliases["account_id"].as_str(),
        Some(authority.to_string().as_str())
    );
    let items = aliases["items"].as_array().expect("original alias rows");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["alias"].as_str(), Some("banking@universal"));
}
#[tokio::test]
async fn alias_resolve_returns_not_found_for_unknown_alias() {
    let authority_keypair = checked_torii_test_ed25519_keypair(
        0x89,
        "derive alias resolve missing-alias authority fixture key",
    );
    let authority = AccountId::new(authority_keypair.public_key().clone());
    let authority_account = Account::new(authority.clone()).build(&authority);
    let app = crate::tests_runtime_handlers::native_ingress_app_with_world_for_test(World::with(
        [],
        [authority_account],
        [],
    ));
    let alias_label =
        AccountAlias::domainless("missing".parse().expect("label"), DataSpaceId::UNIVERSAL);
    let request = routing::AliasResolveRequestDto {
        alias: alias_label
            .to_literal(&app.state.nexus_snapshot().dataspace_catalog)
            .expect("alias literal"),
    };
    let body = norito::json::to_vec(&request).expect("encode request");
    let headers = signed_alias_resolve_headers_for_test(
        &app,
        &authority,
        &authority_keypair,
        &alias_label,
        &body,
    );
    let response = handler_alias_resolve(
        State(app),
        axum::http::Method::POST,
        "/v1/aliases/resolve".parse().expect("alias resolve uri"),
        headers,
        crate::loopback_connect_info(),
        axum::body::Bytes::from(body),
    )
    .await
    .expect("handler should succeed")
    .into_response();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
#[tokio::test]
async fn alias_resolve_service_rejects_non_account_target_as_conflict() {
    let service = AliasService::new(AliasAttester::new(
        KeyPair::try_from_seed(vec![0x8c; 32], Algorithm::Ed25519)
            .expect("derive alias resolve custom-target attester fixture key"),
    ));
    let owner =
        checked_torii_test_account_id(0x8a, "derive alias resolve custom-target owner fixture key");
    let alias_input = "customalias";
    let alias = Name::from_str(&normalise_alias(alias_input)).expect("valid alias");
    service
        .storage()
        .put(AliasRecord::new(
            alias.clone(),
            owner,
            AliasTarget::Custom(vec![0x42]),
            AliasIndex(7),
        ))
        .expect("insert custom alias target");
    let response = resolve_alias_via_service(&service, alias_input)
        .expect("non-account targets should return a response");
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("collect response body");
    let payload: routing::AliasErrorResponseDto =
        norito::json::from_slice(&body).expect("decode alias error");
    assert!(payload.error.contains("custom"));
    assert!(payload.error.contains("account targets"));
}
#[tokio::test]
async fn alias_resolve_index_service_rejects_non_account_target_as_conflict() {
    let service = AliasService::new(AliasAttester::new(
        KeyPair::try_from_seed(vec![0x8d; 32], Algorithm::Ed25519)
            .expect("derive alias resolve index custom-target attester fixture key"),
    ));
    let owner = checked_torii_test_account_id(
        0x8b,
        "derive alias resolve index custom-target owner fixture key",
    );
    let alias = Name::from_str("assetalias").expect("valid alias");
    service
        .storage()
        .put(AliasRecord::new(
            alias,
            owner,
            AliasTarget::Custom(vec![0x24]),
            AliasIndex(11),
        ))
        .expect("insert custom alias target");
    let response = resolve_alias_index_via_service(&service, 11)
        .expect("non-account targets should return a response");
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("collect response body");
    let payload: routing::AliasErrorResponseDto =
        norito::json::from_slice(&body).expect("decode alias error");
    assert!(payload.error.contains("custom"));
    assert!(payload.error.contains("account targets"));
}
#[tokio::test]
async fn alias_resolve_rejects_signed_request_without_exact_permission() {
    let authority_keypair = checked_torii_test_ed25519_keypair(
        0x8c,
        "derive alias resolve permissionless authority fixture key",
    );
    let authority = AccountId::new(authority_keypair.public_key().clone());
    let authority_account = Account::new(authority.clone()).build(&authority);
    let domain_id: DomainId = DomainId::try_new("centralbank", "restricted").expect("domain id");
    let domain = Domain::new(domain_id.clone()).build(&authority);
    let alias_label = AccountAlias::new(
        "banking".parse().expect("label"),
        Some(iroha_data_model::account::rekey::AccountAliasDomain::new(
            "centralbank".parse::<Name>().expect("domain"),
        )),
        DataSpaceId::new(10),
    );
    let app = crate::tests_runtime_handlers::native_ingress_app_with_world_and_nexus_for_test(
        World::with([domain], [authority_account], []),
        crate::tests_runtime_handlers::private_ingress_nexus_for_test(),
    );
    bind_account_alias_for_test(&app, &authority, "banking@centralbank.restricted");
    assert_eq!(
        alias_label
            .to_literal(&app.state.nexus_snapshot().dataspace_catalog)
            .unwrap(),
        "banking@centralbank.restricted"
    );
    let request = routing::AliasResolveRequestDto {
        alias: "banking@centralbank.restricted".to_string(),
    };
    let body = norito::json::to_vec(&request).expect("encode request");
    let method = axum::http::Method::POST;
    let uri: axum::http::Uri = "/v1/aliases/resolve".parse().expect("alias resolve uri");
    let headers = crate::tests_runtime_handlers::signed_network_app_headers(
        app.state.network_id_ref(),
        &authority,
        &authority_keypair,
        &method,
        &uri,
        &body,
    );
    let response = handler_alias_resolve(
        State(app),
        method,
        uri,
        headers,
        crate::loopback_connect_info(),
        axum::body::Bytes::from(body),
    )
    .await
    .expect("authenticated permission denial should be a typed response")
    .into_response();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
#[tokio::test]
async fn alias_resolve_routes_to_matching_dataspace_instead_of_local_default_miss() {
    let authority_keypair = checked_torii_test_ed25519_keypair(
        0x8d,
        "derive alias resolve secondary-dataspace authority fixture key",
    );
    let authority = AccountId::new(authority_keypair.public_key().clone());
    let app = crate::tests_runtime_handlers::native_ingress_app_with_world_and_nexus_for_test(
        world_with_account(&authority),
        crate::tests_runtime_handlers::multiple_dataspace_nexus_for_test(),
    );
    bind_account_alias_for_test(&app, &authority, "merchant@secondary");
    let alias_label = AccountAlias::new(
        "merchant".parse().expect("label"),
        None,
        DataSpaceId::new(1),
    );
    let request = routing::AliasResolveRequestDto {
        alias: "merchant@secondary".to_string(),
    };
    let body = norito::json::to_vec(&request).expect("encode request");
    let default_route = resolve_torii_route_for_dataspace_id(app.as_ref(), DataSpaceId::UNIVERSAL)
        .expect("default route");
    let local_default_response = execute_torii_single_route_read(
        &app,
        default_route,
        ToriiReadEndpointV1::AliasResolve,
        Vec::new(),
        None,
        body.clone(),
    )
    .await;
    assert_eq!(
        local_default_response.status(),
        StatusCode::NOT_FOUND,
        "the default/universal route must not resolve a secondary dataspace alias locally",
    );
    // The response body owns the original query reservation until consumed or dropped.
    drop(local_default_response);
    let headers = signed_alias_resolve_headers_for_test(
        &app,
        &authority,
        &authority_keypair,
        &alias_label,
        &body,
    );
    let response = handler_alias_resolve(
        State(app),
        axum::http::Method::POST,
        "/v1/aliases/resolve".parse().expect("alias resolve uri"),
        headers,
        crate::loopback_connect_info(),
        axum::body::Bytes::from(body),
    )
    .await
    .expect("handler should succeed")
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-route-dataspace-id")
            .and_then(|value| value.to_str().ok()),
        Some("1")
    );
    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    let dto: routing::AliasResolveResponseDto =
        norito::json::from_slice(&body).expect("json decode");
    assert_eq!(dto.alias, "merchant@secondary");
    assert_eq!(dto.account_id, authority.to_string());
}
#[tokio::test]
async fn alias_resolve_allows_signed_exact_permission_for_restricted_target_dataspace() {
    let authority_keypair = checked_torii_test_ed25519_keypair(
        0x8e,
        "derive alias resolve restricted-dataspace authority fixture key",
    );
    let authority = AccountId::new(authority_keypair.public_key().clone());
    let uaid = UniversalAccountId::from_hash(Hash::new(b"torii::alias-resolve-denied"));
    let app = crate::tests_runtime_handlers::native_ingress_app_with_world_and_nexus_for_test(
        world_with_account_bound_to_dataspace(&authority, uaid, DataSpaceId::new(10)),
        crate::tests_runtime_handlers::private_ingress_nexus_for_test(),
    );
    bind_account_alias_for_test(&app, &authority, "merchant@restricted");
    let alias_label = AccountAlias::new(
        "merchant".parse().expect("label"),
        None,
        DataSpaceId::new(10),
    );
    let request = routing::AliasResolveRequestDto {
        alias: "merchant@restricted".to_string(),
    };
    let body = norito::json::to_vec(&request).expect("encode request");
    let headers = signed_alias_resolve_headers_for_test(
        &app,
        &authority,
        &authority_keypair,
        &alias_label,
        &body,
    );
    let response = handler_alias_resolve(
        State(app),
        axum::http::Method::POST,
        "/v1/aliases/resolve".parse().expect("alias resolve uri"),
        headers,
        crate::loopback_connect_info(),
        axum::body::Bytes::from(body),
    )
    .await
    .expect("handler should succeed")
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-route-dataspace-id")
            .and_then(|value| value.to_str().ok()),
        Some("10")
    );
    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    let dto: routing::AliasResolveResponseDto =
        norito::json::from_slice(&body).expect("json decode");
    assert_eq!(dto.alias, "merchant@restricted");
    assert_eq!(dto.account_id, authority.to_string());
}
#[tokio::test]
async fn alias_resolve_reads_local_binding_when_dataspace_has_no_lane() {
    let authority_keypair = checked_torii_test_ed25519_keypair(
        0x8f,
        "derive alias resolve no-lane authority fixture key",
    );
    let authority = AccountId::new(authority_keypair.public_key().clone());
    let lane_catalog = iroha_data_model::nexus::LaneCatalog::new(
        NonZeroU32::new(1).expect("nonzero lane count"),
        vec![iroha_data_model::nexus::LaneConfig::default()],
    )
    .expect("lane catalog");
    let dataspace_catalog = iroha_data_model::nexus::DataSpaceCatalog::new(vec![
        iroha_data_model::nexus::DataSpaceMetadata::default(),
        iroha_data_model::nexus::DataSpaceMetadata {
            id: DataSpaceId::new(10),
            alias: "paynet".to_owned(),
            description: None,
            fault_tolerance: 1,
        },
    ])
    .expect("dataspace catalog");
    let nexus = actual::Nexus {
        lane_config: actual::LaneConfig::from_catalog(&lane_catalog),
        configured_lane_catalog: lane_catalog.clone(),
        configured_dataspace_catalog: dataspace_catalog.clone(),
        lane_catalog,
        dataspace_catalog,
        ..actual::Nexus::default()
    };
    let app = crate::tests_runtime_handlers::native_ingress_app_with_world_and_nexus_for_test(
        world_with_account(&authority),
        nexus,
    );
    assert!(
        matches!(
            resolve_torii_route_for_dataspace_id(app.as_ref(), DataSpaceId::new(10)),
            Err(queue::RoutingResolveError::NoLaneForDataspace { dataspace_id })
                if dataspace_id == DataSpaceId::new(10)
        ),
        "an unrelated global lane must not be advertised as the target's lane"
    );
    bind_account_alias_for_test(&app, &authority, "banking@paynet");
    let alias_label = AccountAlias::new(
        "banking".parse().expect("label"),
        None,
        DataSpaceId::new(10),
    );
    let request = routing::AliasResolveRequestDto {
        alias: "banking@paynet".to_string(),
    };
    let body = norito::json::to_vec(&request).expect("encode request");
    let headers = signed_alias_resolve_headers_for_test(
        &app,
        &authority,
        &authority_keypair,
        &alias_label,
        &body,
    );
    let response = handler_alias_resolve(
        State(app),
        axum::http::Method::POST,
        "/v1/aliases/resolve".parse().expect("alias resolve uri"),
        headers,
        crate::loopback_connect_info(),
        axum::body::Bytes::from(body),
    )
    .await
    .expect("handler should read local native alias state")
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    let dto: routing::AliasResolveResponseDto =
        norito::json::from_slice(&body).expect("json decode");
    assert_eq!(dto.alias, "banking@paynet");
    assert_eq!(dto.account_id, authority.to_string());
    assert_eq!(dto.source.as_deref(), Some("active_sns"));
}
#[tokio::test]
async fn alias_resolve_returns_route_unavailable_when_authoritative_route_is_offline() {
    let authority_keypair = checked_torii_test_ed25519_keypair(
        0x90,
        "derive alias resolve offline-route authority fixture key",
    );
    let authority = AccountId::new(authority_keypair.public_key().clone());
    let uaid = UniversalAccountId::from_hash(Hash::new(b"torii::alias-resolve-offline"));
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
        world_with_account_bound_to_dataspace(&authority, uaid, DataSpaceId::new(12)),
        crate::tests_runtime_handlers::private_ingress_with_offline_foreign_nexus_for_test(),
    );
    let (_local_route, _foreign_route) =
            crate::tests_runtime_handlers::configure_private_ingress_with_offline_foreign_route_for_test(
                &mut app,
        );
    bind_account_alias_for_test(&app, &authority, "merchant@foreign-restricted");
    let alias_label = AccountAlias::new(
        "merchant".parse().expect("label"),
        None,
        DataSpaceId::new(12),
    );
    grant_alias_resolve_permissions(&app, &authority, &alias_label);
    let request = routing::AliasResolveRequestDto {
        alias: "merchant@foreign-restricted".to_string(),
    };
    let body = norito::json::to_vec(&request).expect("encode request");
    let method = axum::http::Method::POST;
    let uri: axum::http::Uri = "/v1/aliases/resolve".parse().expect("alias resolve uri");
    let headers = signed_app_headers(&authority, &authority_keypair, &method, &uri, &body);
    let response = handler_alias_resolve(
        State(app),
        method,
        uri,
        headers,
        crate::loopback_connect_info(),
        axum::body::Bytes::from(body),
    )
    .await
    .expect("handler should return a routed response")
    .into_response();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-reject-code")
            .and_then(|value| value.to_str().ok()),
        Some("route_unavailable")
    );
}
#[tokio::test]
async fn alias_resolve_rejects_empty_alias() {
    let authority_keypair = checked_torii_test_ed25519_keypair(
        0x95,
        "derive alias resolve empty-alias authority fixture key",
    );
    let authority = AccountId::new(authority_keypair.public_key().clone());
    let app = mk_app_state_for_tests_with_world(world_with_account(&authority));
    for (alias, expected) in [
        ("", "account alias must not be empty"),
        (
            "   ",
            "account alias must not contain leading or trailing whitespace",
        ),
    ] {
        let request = routing::AliasResolveRequestDto {
            alias: alias.to_owned(),
        };
        let body = norito::json::to_vec(&request).expect("encode request");
        let method = axum::http::Method::POST;
        let uri: axum::http::Uri = "/v1/aliases/resolve".parse().expect("alias resolve uri");
        let headers = signed_app_headers(&authority, &authority_keypair, &method, &uri, &body);
        let err = handler_alias_resolve(
            State(app.clone()),
            method,
            uri,
            headers,
            crate::loopback_connect_info(),
            axum::body::Bytes::from(body),
        )
        .await
        .expect_err("empty alias requests should be rejected");
        match err {
            Error::Query(ValidationFail::QueryFailed(
                iroha_data_model::query::error::QueryExecutionFail::Conversion(message),
            )) => assert_eq!(message, expected),
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
#[tokio::test]
async fn alias_resolve_rejects_noncanonical_exact_literal() {
    let authority_keypair =
        checked_torii_test_ed25519_keypair(0x91, "derive noncanonical exact alias fixture key");
    let authority = AccountId::new(authority_keypair.public_key().clone());
    let app = mk_app_state_for_tests_with_world(world_with_account(&authority));
    let body = norito::json::to_vec(&routing::AliasResolveRequestDto {
        alias: " banking@universal".to_owned(),
    })
    .expect("encode request");
    let method = axum::http::Method::POST;
    let uri: axum::http::Uri = "/v1/aliases/resolve".parse().expect("alias resolve uri");
    let headers = signed_app_headers(&authority, &authority_keypair, &method, &uri, &body);
    let error = handler_alias_resolve(
        State(app),
        method,
        uri,
        headers,
        crate::loopback_connect_info(),
        axum::body::Bytes::from(body),
    )
    .await
    .expect_err("noncanonical exact aliases must be rejected");
    assert!(matches!(
        error,
        Error::Query(ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::Conversion(_)
        ))
    ));
}
#[tokio::test]
async fn alias_resolve_rejects_malformed_alias_literal() {
    let authority_keypair = checked_torii_test_ed25519_keypair(
        0x96,
        "derive alias resolve malformed-alias authority fixture key",
    );
    let authority = AccountId::new(authority_keypair.public_key().clone());
    let app = mk_app_state_for_tests_with_world(world_with_account(&authority));
    let request = routing::AliasResolveRequestDto {
        alias: "merchant@missing-dataspace".to_string(),
    };
    let body = norito::json::to_vec(&request).expect("encode request");
    let method = axum::http::Method::POST;
    let uri: axum::http::Uri = "/v1/aliases/resolve".parse().expect("alias resolve uri");
    let headers = signed_app_headers(&authority, &authority_keypair, &method, &uri, &body);
    let err = handler_alias_resolve(
        State(app),
        method,
        uri,
        headers,
        crate::loopback_connect_info(),
        axum::body::Bytes::from(body),
    )
    .await
    .expect_err("malformed alias literals should be rejected");
    match err {
        Error::Query(ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::Conversion(message),
        )) => assert!(
            !message.trim().is_empty(),
            "conversion errors should surface a diagnostic message"
        ),
        other => panic!("unexpected error: {other:?}"),
    }
}
#[tokio::test]
async fn alias_resolve_rejects_malformed_json_body() {
    let authority_keypair = checked_torii_test_ed25519_keypair(
        0x97,
        "derive alias resolve malformed-json authority fixture key",
    );
    let authority = AccountId::new(authority_keypair.public_key().clone());
    let app = mk_app_state_for_tests_with_world(world_with_account(&authority));
    let body = b"{";
    let method = axum::http::Method::POST;
    let uri: axum::http::Uri = "/v1/aliases/resolve".parse().expect("alias resolve uri");
    let headers = signed_app_headers(&authority, &authority_keypair, &method, &uri, body);
    let err = handler_alias_resolve(
        State(app),
        method,
        uri,
        headers,
        crate::loopback_connect_info(),
        axum::body::Bytes::from_static(body),
    )
    .await
    .expect_err("malformed alias-resolve bodies should be rejected");
    match err {
        Error::Query(ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::Conversion(message),
        )) => assert!(
            !message.trim().is_empty(),
            "malformed request bodies should surface a parse diagnostic"
        ),
        other => panic!("unexpected error: {other:?}"),
    }
}
#[test]
fn exact_alias_request_dtos_reject_unknown_fields() {
    assert!(
        norito::json::from_slice::<routing::AliasResolveRequestDto>(
            br#"{"alias":"merchant@universal","prefix":true}"#,
        )
        .is_err()
    );
    assert!(
            norito::json::from_slice::<routing::AliasLookupByAccountRequestDto>(
                r#"{"account_id":"sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV","cursor":"enumerate"}"#
                    .as_bytes(),
            )
            .is_err()
        );
}
#[tokio::test]
async fn alias_lookup_by_account_lists_primary_and_secondary_aliases() {
    let authority_keypair = checked_torii_test_ed25519_keypair(
        0xa0,
        "derive alias lookup primary-secondary authority fixture key",
    );
    let authority = AccountId::new(authority_keypair.public_key().clone());
    let primary_label = AccountAlias::new(
        "banking".parse().expect("label"),
        Some(iroha_data_model::account::rekey::AccountAliasDomain::new(
            "centralbank".parse::<Name>().expect("domain id"),
        )),
        DataSpaceId::UNIVERSAL,
    );
    let authority_account = Account::new(authority.clone()).build(&authority);
    let domain = Domain::new(DomainId::try_new("centralbank", "universal").expect("domain id"))
        .build(&authority);
    let app = crate::tests_runtime_handlers::native_ingress_app_with_world_for_test(World::with(
        [domain],
        [authority_account],
        [],
    ));
    bind_primary_account_alias_for_test(&app, &authority, &primary_label);
    bind_account_alias_for_test(&app, &authority, "public@universal");
    grant_alias_resolve_permissions(&app, &authority, &primary_label);
    let request = routing::AliasLookupByAccountRequestDto {
        account_id: authority.to_string(),
        dataspace: None,
        domain: None,
    };
    let body = norito::json::to_vec(&request).expect("encode request");
    let method = Method::POST;
    let uri: axum::http::Uri = "/v1/aliases/by-account"
        .parse()
        .expect("alias by-account uri");
    let headers = crate::tests_runtime_handlers::signed_network_app_headers(
        app.state.network_id_ref(),
        &authority,
        &authority_keypair,
        &method,
        &uri,
        &body,
    );
    let response = handler_alias_lookup_by_account(
        State(app),
        method,
        uri,
        headers,
        axum::body::Bytes::from(body),
    )
    .await
    .expect("handler should succeed")
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    let dto: routing::AliasLookupByAccountResponseDto =
        norito::json::from_slice(&body).expect("json decode");
    assert_eq!(dto.total, 2);
    assert_eq!(
        dto.items.iter().filter(|item| item.is_primary).count(),
        1,
        "exactly one primary alias should be reported"
    );
    assert!(
        dto.items
            .iter()
            .any(|item| item.alias == "banking@centralbank.universal"),
        "primary alias should be present"
    );
    assert!(
        dto.items
            .iter()
            .any(|item| item.alias == "public@universal"),
        "secondary alias should be present"
    );
}
#[tokio::test]
async fn alias_lookup_by_account_output_is_sorted_and_bounded() {
    let item = |alias: String| routing::AliasLookupByAccountItemDto {
        alias,
        dataspace: "universal".to_owned(),
        domain: None,
        is_primary: false,
    };
    let response = alias_lookup_by_account_ok(
        "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
        vec![
            item("zeta@universal".to_owned()),
            item("alpha@universal".to_owned()),
        ],
        "on_chain",
    )
    .expect("bounded response should encode")
    .into_response();
    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .expect("collect response")
        .to_bytes();
    let dto: routing::AliasLookupByAccountResponseDto =
        norito::json::from_slice(&body).expect("decode response");
    assert_eq!(
        dto.items
            .iter()
            .map(|entry| entry.alias.as_str())
            .collect::<Vec<_>>(),
        vec!["alpha@universal", "zeta@universal"]
    );
    let oversized = (0..=EXACT_ALIAS_LOOKUP_MAX_ITEMS)
        .map(|index| item(format!("alias{index:03}@universal")))
        .collect();
    assert!(matches!(
        alias_lookup_by_account_ok(
            "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
            oversized,
            "on_chain"
        ),
        Err(Error::Query(ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::CapacityLimit
        )))
    ));
}
#[tokio::test]
async fn alias_lookup_by_account_filters_by_dataspace_and_domain() {
    let authority_keypair = checked_torii_test_ed25519_keypair(
        0xa1,
        "derive alias lookup filtered authority fixture key",
    );
    let authority = AccountId::new(authority_keypair.public_key().clone());
    let primary_label = AccountAlias::new(
        "banking".parse().expect("label"),
        Some(iroha_data_model::account::rekey::AccountAliasDomain::new(
            "centralbank".parse::<Name>().expect("domain id"),
        )),
        DataSpaceId::UNIVERSAL,
    );
    let authority_account = Account::new(authority.clone()).build(&authority);
    let domain = Domain::new(DomainId::try_new("centralbank", "universal").expect("domain id"))
        .build(&authority);
    let app = crate::tests_runtime_handlers::native_ingress_app_with_world_for_test(World::with(
        [domain],
        [authority_account],
        [],
    ));
    bind_primary_account_alias_for_test(&app, &authority, &primary_label);
    grant_alias_resolve_permissions(&app, &authority, &primary_label);
    let request = routing::AliasLookupByAccountRequestDto {
        account_id: authority.to_string(),
        dataspace: Some("universal".to_string()),
        domain: Some("centralbank".to_string()),
    };
    let body = norito::json::to_vec(&request).expect("encode request");
    let method = Method::POST;
    let uri: axum::http::Uri = "/v1/aliases/by-account"
        .parse()
        .expect("alias by-account uri");
    let headers = crate::tests_runtime_handlers::signed_network_app_headers(
        app.state.network_id_ref(),
        &authority,
        &authority_keypair,
        &method,
        &uri,
        &body,
    );
    let response = handler_alias_lookup_by_account(
        State(app),
        method,
        uri,
        headers,
        axum::body::Bytes::from(body),
    )
    .await
    .expect("handler should succeed")
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    let dto: routing::AliasLookupByAccountResponseDto =
        norito::json::from_slice(&body).expect("json decode");
    assert_eq!(dto.total, 1);
    assert_eq!(dto.items[0].alias, "banking@centralbank.universal");
    assert!(dto.items[0].is_primary);
}
#[tokio::test]
async fn alias_lookup_by_account_returns_not_found_for_unknown_account() {
    let authority_keypair =
        checked_torii_test_ed25519_keypair(0xa2, "derive alias lookup known authority fixture key");
    let authority = AccountId::new(authority_keypair.public_key().clone());
    let authority_account = Account::new(authority.clone()).build(&authority);
    let app = crate::tests_runtime_handlers::native_ingress_app_with_world_for_test(World::with(
        [],
        [authority_account],
        [],
    ));
    let missing =
        checked_torii_test_account_id(0xa3, "derive alias lookup missing account fixture key");
    let request = routing::AliasLookupByAccountRequestDto {
        account_id: missing.to_string(),
        dataspace: None,
        domain: None,
    };
    let body = norito::json::to_vec(&request).expect("encode request");
    let method = Method::POST;
    let uri: axum::http::Uri = "/v1/aliases/by-account"
        .parse()
        .expect("alias by-account uri");
    let headers = crate::tests_runtime_handlers::signed_network_app_headers(
        app.state.network_id_ref(),
        &authority,
        &authority_keypair,
        &method,
        &uri,
        &body,
    );
    let response = handler_alias_lookup_by_account(
        State(app),
        method,
        uri,
        headers,
        axum::body::Bytes::from(body),
    )
    .await
    .expect("handler should succeed")
    .into_response();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
#[tokio::test]
async fn alias_lookup_by_account_rejects_invalid_account_id() {
    let authority_keypair = checked_torii_test_ed25519_keypair(
        0xa4,
        "derive alias lookup invalid-account authority fixture key",
    );
    let authority = AccountId::new(authority_keypair.public_key().clone());
    let app = mk_app_state_for_tests_with_world(world_with_account(&authority));
    let request = routing::AliasLookupByAccountRequestDto {
        account_id: "not-an-account".to_string(),
        dataspace: None,
        domain: None,
    };
    let body = norito::json::to_vec(&request).expect("encode request");
    let method = Method::POST;
    let uri: axum::http::Uri = "/v1/aliases/by-account"
        .parse()
        .expect("alias by-account uri");
    let headers = signed_app_headers(&authority, &authority_keypair, &method, &uri, &body);
    let err = handler_alias_lookup_by_account(
        State(app),
        method,
        uri,
        headers,
        axum::body::Bytes::from(body),
    )
    .await
    .expect_err("invalid account ids should be rejected");
    match err {
        Error::Query(ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::Conversion(message),
        )) => assert!(
            message.starts_with("invalid account_id:"),
            "unexpected conversion message: {message}"
        ),
        other => panic!("unexpected error: {other:?}"),
    }
}
#[tokio::test]
async fn alias_lookup_by_account_rejects_empty_account_id() {
    let authority_keypair = checked_torii_test_ed25519_keypair(
        0xa5,
        "derive alias lookup empty-account authority fixture key",
    );
    let authority = AccountId::new(authority_keypair.public_key().clone());
    let app = mk_app_state_for_tests_with_world(world_with_account(&authority));
    let request = routing::AliasLookupByAccountRequestDto {
        account_id: "   ".to_string(),
        dataspace: None,
        domain: None,
    };
    let body = norito::json::to_vec(&request).expect("encode request");
    let method = Method::POST;
    let uri: axum::http::Uri = "/v1/aliases/by-account"
        .parse()
        .expect("alias by-account uri");
    let headers = signed_app_headers(&authority, &authority_keypair, &method, &uri, &body);
    let err = handler_alias_lookup_by_account(
        State(app),
        method,
        uri,
        headers,
        axum::body::Bytes::from(body),
    )
    .await
    .expect_err("empty account ids should be rejected");
    match err {
        Error::Query(ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::Conversion(message),
        )) => assert_eq!(message, "account_id must not be empty"),
        other => panic!("unexpected error: {other:?}"),
    }
}
#[tokio::test]
async fn alias_lookup_by_account_rejects_noncanonical_account_or_scope() {
    let authority_keypair =
        checked_torii_test_ed25519_keypair(0xa6, "derive noncanonical reverse alias fixture key");
    let authority = AccountId::new(authority_keypair.public_key().clone());
    let app = mk_app_state_for_tests_with_world(world_with_account(&authority));
    let account_body = norito::json::to_vec(&routing::AliasLookupByAccountRequestDto {
        account_id: format!(" {}", authority),
        dataspace: None,
        domain: None,
    })
    .expect("encode request");
    let method = Method::POST;
    let uri: axum::http::Uri = "/v1/aliases/by-account"
        .parse()
        .expect("alias by-account uri");
    let account_headers =
        signed_app_headers(&authority, &authority_keypair, &method, &uri, &account_body);
    handler_alias_lookup_by_account(
        State(app.clone()),
        method.clone(),
        uri.clone(),
        account_headers,
        axum::body::Bytes::from(account_body),
    )
    .await
    .expect_err("noncanonical account literals must be rejected");
    let scope_body = norito::json::to_vec(&routing::AliasLookupByAccountRequestDto {
        account_id: authority.to_string(),
        dataspace: Some(" universal".to_owned()),
        domain: None,
    })
    .expect("encode request");
    let scope_headers =
        signed_app_headers(&authority, &authority_keypair, &method, &uri, &scope_body);
    handler_alias_lookup_by_account(
        State(app),
        method,
        uri,
        scope_headers,
        axum::body::Bytes::from(scope_body),
    )
    .await
    .expect_err("noncanonical scope filters must be rejected");
}
#[tokio::test]
async fn alias_lookup_by_account_rejects_malformed_json_body() {
    let authority_keypair = checked_torii_test_ed25519_keypair(
        0xa6,
        "derive alias lookup malformed-json authority fixture key",
    );
    let authority = AccountId::new(authority_keypair.public_key().clone());
    let app = mk_app_state_for_tests_with_world(world_with_account(&authority));
    let method = axum::http::Method::POST;
    let uri: axum::http::Uri = "/v1/aliases/by-account"
        .parse()
        .expect("alias by-account uri");
    let body = b"{";
    let headers = signed_app_headers(&authority, &authority_keypair, &method, &uri, body);
    let err = handler_alias_lookup_by_account(
        State(app),
        method,
        uri,
        headers,
        axum::body::Bytes::from_static(body),
    )
    .await
    .expect_err("malformed alias by-account bodies should be rejected");
    match err {
        Error::Query(ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::Conversion(message),
        )) => assert!(
            !message.trim().is_empty(),
            "malformed request bodies should surface a parse diagnostic"
        ),
        other => panic!("unexpected error: {other:?}"),
    }
}
#[tokio::test]
async fn alias_lookup_by_account_merges_cross_dataspace_aliases_and_recomputes_total() {
    let authority_keypair = checked_torii_test_ed25519_keypair(
        0xa7,
        "derive alias lookup fanout authority fixture key",
    );
    let authority = AccountId::new(authority_keypair.public_key().clone());
    let uaid = UniversalAccountId::from_hash(Hash::new(b"torii::alias-lookup-fanout"));
    let app = crate::tests_runtime_handlers::native_ingress_app_with_world_and_nexus_for_test(
        world_with_account_bound_to_dataspace(&authority, uaid, DataSpaceId::new(10)),
        crate::tests_runtime_handlers::private_ingress_nexus_for_test(),
    );
    bind_account_alias_for_test(&app, &authority, "merchant@universal");
    bind_account_alias_for_test(&app, &authority, "merchant@restricted");
    let catalog = app.state.nexus_snapshot().dataspace_catalog;
    for alias_literal in ["merchant@universal", "merchant@restricted"] {
        let alias =
            AccountAlias::from_literal(alias_literal, &catalog).expect("configured account alias");
        grant_alias_resolve_permissions(&app, &authority, &alias);
    }
    let request = routing::AliasLookupByAccountRequestDto {
        account_id: authority.to_string(),
        dataspace: None,
        domain: None,
    };
    let body = norito::json::to_vec(&request).expect("encode request");
    let method = axum::http::Method::POST;
    let uri: axum::http::Uri = "/v1/aliases/by-account"
        .parse()
        .expect("alias by-account uri");
    let headers = crate::tests_runtime_handlers::signed_network_app_headers(
        app.state.network_id_ref(),
        &authority,
        &authority_keypair,
        &method,
        &uri,
        &body,
    );
    let response = handler_alias_lookup_by_account(
        State(app),
        method,
        uri,
        headers,
        axum::body::Bytes::from(body),
    )
    .await
    .expect("handler should succeed")
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-fanout-routes-attempted")
            .and_then(|value| value.to_str().ok()),
        Some("3")
    );
    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    let dto: routing::AliasLookupByAccountResponseDto =
        norito::json::from_slice(&body).expect("json decode");
    assert_eq!(dto.account_id, authority.to_string());
    assert_eq!(dto.total, 2);
    assert_eq!(dto.source.as_deref(), Some("fanout"));
    assert!(
        dto.items
            .iter()
            .any(|item| item.alias == "merchant@universal"),
        "merged response should include the universal alias"
    );
    assert!(
        dto.items
            .iter()
            .any(|item| item.alias == "merchant@restricted"),
        "merged response should include the restricted alias"
    );
}

include!("alias_error_envelopes.rs");
