#[tokio::test]
async fn alias_lookup_by_account_unsigned_read_returns_only_public_aliases() {
    let authority = checked_torii_test_account_id(
        0xa8,
        "derive unsigned alias lookup filtering authority fixture key",
    );
    let uaid = UniversalAccountId::from_hash(Hash::new(b"torii::alias-warning-fanout"));
    let app = crate::tests_runtime_handlers::native_ingress_app_with_world_and_nexus_for_test(
        world_with_account_bound_to_dataspace(&authority, uaid, DataSpaceId::new(10)),
        crate::tests_runtime_handlers::private_ingress_nexus_for_test(),
    );
    bind_account_alias_for_test(&app, &authority, "merchant@universal");
    bind_account_alias_for_test(&app, &authority, "merchant@restricted");
    let request = routing::AliasLookupByAccountRequestDto {
        account_id: authority.to_string(),
        dataspace: None,
        domain: None,
    };
    let body = norito::json::to_vec(&request).expect("encode request");
    let response = handler_alias_lookup_by_account(
        State(app),
        axum::http::Method::POST,
        "/v1/aliases/by-account"
            .parse()
            .expect("alias by-account uri"),
        HeaderMap::new(),
        axum::body::Bytes::from(body),
    )
    .await
    .expect("unsigned lookup should return only visible public aliases")
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .expect("collect public alias lookup response")
        .to_bytes();
    let dto: routing::AliasLookupByAccountResponseDto =
        norito::json::from_slice(&body).expect("decode public alias lookup response");
    assert_eq!(dto.total, 1);
    assert_eq!(dto.items[0].alias, "merchant@universal");
}
#[tokio::test]
async fn alias_lookup_by_account_rejects_unsigned_restricted_alias_lookup() {
    let authority = checked_torii_test_account_id(
        0xa9,
        "derive alias lookup hidden-route authority fixture key",
    );
    let uaid = UniversalAccountId::from_hash(Hash::new(b"torii::alias-denied-fanout"));
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
        world_with_account_bound_to_dataspace(&authority, uaid, DataSpaceId::new(10)),
        crate::tests_runtime_handlers::private_ingress_nexus_for_test(),
    );
    configure_private_ingress_routes_for_test(&mut app);
    bind_account_alias_for_test(&app, &authority, "merchant@restricted");
    let request = routing::AliasLookupByAccountRequestDto {
        account_id: authority.to_string(),
        dataspace: Some("restricted".to_owned()),
        domain: None,
    };
    let body = norito::json::to_vec(&request).expect("encode request");
    let error = handler_alias_lookup_by_account(
        State(app),
        axum::http::Method::POST,
        "/v1/aliases/by-account"
            .parse()
            .expect("alias by-account uri"),
        HeaderMap::new(),
        axum::body::Bytes::from(body),
    )
    .await
    .expect_err("unsigned restricted alias lookup must fail closed");
    assert!(matches!(
        &error,
        Error::AppUnauthorized {
            code: "alias_auth_required",
            ..
        }
    ));
    assert_eq!(error.into_response().status(), StatusCode::UNAUTHORIZED);
}
#[tokio::test]
async fn alias_lookup_by_account_rejects_invalid_auth_for_restricted_filter() {
    let authority = checked_torii_test_account_id(
        0xb0,
        "derive invalid restricted alias lookup auth fixture key",
    );
    let uaid = UniversalAccountId::from_hash(Hash::new(b"torii::alias-invalid-auth"));
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
        world_with_account_bound_to_dataspace(&authority, uaid, DataSpaceId::new(10)),
        crate::tests_runtime_handlers::private_ingress_nexus_for_test(),
    );
    configure_private_ingress_routes_for_test(&mut app);
    let request = routing::AliasLookupByAccountRequestDto {
        account_id: authority.to_string(),
        dataspace: Some("restricted".to_owned()),
        domain: None,
    };
    let body = norito::json::to_vec(&request).expect("encode request");
    let mut headers = HeaderMap::new();
    headers.insert(
        HEADER_ACCOUNT,
        authority
            .to_canonical_hex()
            .expect("canonical account header")
            .parse()
            .expect("account header"),
    );
    let error = handler_alias_lookup_by_account(
        State(app),
        axum::http::Method::POST,
        "/v1/aliases/by-account"
            .parse()
            .expect("alias by-account uri"),
        headers,
        axum::body::Bytes::from(body),
    )
    .await
    .expect_err("incomplete canonical authentication must fail closed");
    assert!(matches!(
        &error,
        Error::AppUnauthorized {
            code: "alias_auth_invalid",
            ..
        }
    ));
    assert_eq!(error.into_response().status(), StatusCode::UNAUTHORIZED);
}
#[tokio::test]
async fn alias_lookup_by_account_explicit_restricted_filter_requires_exact_resolve_permission() {
    let caller_keypair = checked_torii_test_ed25519_keypair(
        0x35,
        "derive alias lookup permission caller fixture key",
    );
    let caller = AccountId::new(caller_keypair.public_key().clone());
    let target =
        checked_torii_test_account_id(0x36, "derive alias lookup permission target fixture key");
    let uaid = UniversalAccountId::from_hash(Hash::new(b"torii::alias-permission-fanout"));
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
        world_with_target_and_caller_bound_to_dataspace(
            &target,
            &caller,
            uaid,
            DataSpaceId::new(10),
        ),
        crate::tests_runtime_handlers::private_ingress_nexus_for_test(),
    );
    configure_private_ingress_routes_for_test(&mut app);
    bind_account_alias_for_test(&app, &target, "merchant@restricted");
    let request = routing::AliasLookupByAccountRequestDto {
        account_id: target.to_string(),
        dataspace: Some("restricted".to_owned()),
        domain: None,
    };
    let body = norito::json::to_vec(&request).expect("encode request");
    let method = axum::http::Method::POST;
    let uri: axum::http::Uri = "/v1/aliases/by-account"
        .parse()
        .expect("alias by-account uri");
    let headers = signed_app_headers(&caller, &caller_keypair, &method, &uri, &body);
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
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
#[tokio::test]
async fn account_alias_enumeration_rejects_signed_caller_without_exact_scope() {
    let caller_keypair = checked_torii_test_ed25519_keypair(
        0x39,
        "derive account alias enumeration caller fixture key",
    );
    let caller = AccountId::new(caller_keypair.public_key().clone());
    let target =
        checked_torii_test_account_id(0x3a, "derive account alias enumeration target fixture key");
    let world = World::with(
        [],
        [
            Account::new(caller.clone()).build(&caller),
            Account::new(target.clone()).build(&target),
        ],
        [],
    );
    let app = mk_app_state_for_tests_with_world(world);
    bind_account_alias_for_test(&app, &target, "merchant@universal");
    let method = Method::GET;
    let uri: axum::http::Uri = format!("/v1/accounts/{target}/aliases")
        .parse()
        .expect("account aliases uri");
    let headers = signed_app_headers(&caller, &caller_keypair, &method, &uri, &[]);
    let error = match handler_account_aliases(
        State(app),
        method,
        uri,
        headers,
        crate::loopback_connect_info(),
        AxPath(target.to_string()),
    )
    .await
    {
        Err(error) => error,
        Ok(_) => panic!("caller without exact alias scope must not enumerate bindings"),
    };
    assert!(matches!(
        error,
        Error::Query(ValidationFail::NotPermitted(message))
            if message == "exact account-alias resolve permission is required"
    ));
}
#[tokio::test]
async fn alias_lookup_by_account_filters_domain_aliases_until_exact_domain_grant() {
    let caller_keypair = checked_torii_test_ed25519_keypair(
        0x37,
        "derive alias lookup permission filter caller fixture key",
    );
    let caller = AccountId::new(caller_keypair.public_key().clone());
    let target = checked_torii_test_account_id(
        0x38,
        "derive alias lookup permission filter target fixture key",
    );
    let restricted_dataspace = DataSpaceId::new(10);
    let uaid = UniversalAccountId::from_hash(Hash::new(b"torii::alias-permission-filter-fanout"));
    let app = crate::tests_runtime_handlers::native_ingress_app_with_world_and_nexus_for_test(
        world_with_target_and_caller_bound_to_dataspace(
            &target,
            &caller,
            uaid,
            restricted_dataspace,
        ),
        crate::tests_runtime_handlers::private_ingress_nexus_for_test(),
    );
    bind_account_alias_for_test(&app, &target, "merchant@restricted");
    bind_account_alias_for_test(&app, &target, "merchant@bank.restricted");
    grant_alias_resolve_dataspace_permission(&app, &caller, restricted_dataspace);
    let request = routing::AliasLookupByAccountRequestDto {
        account_id: target.to_string(),
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
        &caller,
        &caller_keypair,
        &method,
        &uri,
        &body,
    );
    let response = handler_alias_lookup_by_account(
        State(app.clone()),
        method.clone(),
        uri.clone(),
        headers.clone(),
        axum::body::Bytes::from(body.clone()),
    )
    .await
    .expect("handler should succeed")
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let response_body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    let dto: routing::AliasLookupByAccountResponseDto =
        norito::json::from_slice(&response_body).expect("json decode");
    assert_eq!(dto.total, 1);
    assert_eq!(dto.items[0].alias, "merchant@restricted");
    let domain_alias = AccountAlias::from_literal(
        "merchant@bank.restricted",
        &app.state.nexus_snapshot().dataspace_catalog,
    )
    .expect("domain alias");
    grant_alias_resolve_permissions(&app, &caller, &domain_alias);
    let headers = crate::tests_runtime_handlers::signed_network_app_headers(
        app.state.network_id_ref(),
        &caller,
        &caller_keypair,
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
    .expect("handler should succeed after exact domain grant")
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    let dto: routing::AliasLookupByAccountResponseDto =
        norito::json::from_slice(&body).expect("json decode");
    assert_eq!(dto.total, 2);
    assert!(
        dto.items
            .iter()
            .any(|item| item.alias == "merchant@bank.restricted")
    );
}
#[tokio::test]
async fn alias_lookup_by_account_returns_empty_fanout_result_when_offline_route_has_no_reachable_aliases()
 {
    let authority_keypair = checked_torii_test_ed25519_keypair(
        0xaa,
        "derive alias lookup offline fanout authority fixture key",
    );
    let authority = AccountId::new(authority_keypair.public_key().clone());
    let uaid = UniversalAccountId::from_hash(Hash::new(b"torii::alias-lookup-offline"));
    let app = crate::tests_runtime_handlers::native_ingress_app_with_world_and_nexus_for_test(
        world_with_account_bound_to_dataspace(&authority, uaid, DataSpaceId::new(12)),
        crate::tests_runtime_handlers::private_ingress_with_offline_foreign_nexus_for_test(),
    );
    bind_account_alias_for_test(&app, &authority, "merchant@foreign-restricted");
    let alias = AccountAlias::from_literal(
        "merchant@foreign-restricted",
        &app.state.nexus_snapshot().dataspace_catalog,
    )
    .expect("foreign account alias");
    grant_alias_resolve_permissions(&app, &authority, &alias);
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
    // All active labels share the authenticated global committee. A signed
    // handler request must therefore find this alias while transport is healthy.
    let live = handler_alias_lookup_by_account(
        State(app.clone()),
        method.clone(),
        uri.clone(),
        headers,
        axum::body::Bytes::from(body.clone()),
    )
    .await
    .expect("signed native handler read")
    .into_response();
    assert_eq!(live.status(), StatusCode::OK);
    let live_bytes = axum::body::to_bytes(live.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let live_dto: routing::AliasLookupByAccountResponseDto =
        norito::json::from_slice(&live_bytes).unwrap();
    assert_eq!(live_dto.total, 1);
    assert_eq!(live_dto.items[0].alias, "merchant@foreign-restricted");

    let headers = crate::tests_runtime_handlers::signed_network_app_headers(
        app.state.network_id_ref(),
        &authority,
        &authority_keypair,
        &method,
        &uri,
        &body,
    );
    let visibility = torii_visibility_account_from_headers(
        &app,
        &headers,
        &method,
        &uri,
        &body,
        "alias_lookup_by_account",
    )
    .expect("original signed caller");
    let routes = torii_target_account_routes(app.as_ref(), &authority).unwrap();
    let (allowed, denied) =
        torii_partition_alias_lookup_routes(&app, routes, &visibility, &request).unwrap();
    let _reservation = try_acquire_query_fanout_memory(&app).unwrap();
    // Isolate a transient fetch failure at the real collector boundary; do not
    // manufacture a different committee for one routing label. Other fetches
    // execute the same original State reader as the production handler.
    let collected = collect_torii_alias_lookup_json_payloads(
        &app,
        &allowed,
        (denied, "unresolved alias routes require permission"),
        visibility.caller(),
        &request,
        (
            app.query_fanout_working_set_bytes,
            app.torii_proxy_max_response_bytes,
        ),
        |route| {
            let app = &app;
            let body = &body;
            async move {
                if route.dataspace_id == DataSpaceId::new(12) {
                    torii_proxy_error_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "route_unavailable",
                        "authoritative transport unavailable",
                    )
                } else {
                    execute_torii_single_route_read_in_fanout(
                        app,
                        route,
                        ToriiReadEndpointV1::AliasLookupByAccount,
                        Vec::new(),
                        None,
                        body,
                        body.clone(),
                    )
                    .await
                }
            }
        },
    )
    .await
    .expect("reachable empty route remains a completed response");
    let diagnostics = collected.diagnostics;
    let response = merge_with_torii_fanout_headers(diagnostics, || {
        merged_alias_lookup_by_account_response(
            collected.payloads,
            "proxy",
            "fanout",
            diagnostics.denied_routes,
            collected.budget,
        )
    });
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-routed-by")
            .and_then(|value| value.to_str().ok()),
        Some("proxy")
    );
    assert_eq!(
        response
            .headers()
            .get("x-iroha-fanout-routes-unavailable")
            .and_then(|value| value.to_str().ok()),
        Some("1")
    );
    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    let dto: routing::AliasLookupByAccountResponseDto =
        norito::json::from_slice(&body).expect("json decode");
    assert_eq!(dto.account_id, authority.to_string());
    assert_eq!(dto.total, 0);
    assert!(dto.items.is_empty());
    assert_eq!(dto.source.as_deref(), Some("fanout"));
}
#[tokio::test]
async fn alias_resolve_rejects_account_label_without_authoritative_binding() {
    let alias = "banking@centralbank.universal";
    let alias_label = iroha_data_model::account::rekey::AccountAlias::new(
        "banking".parse::<Name>().expect("label"),
        Some(iroha_data_model::account::rekey::AccountAliasDomain::new(
            "centralbank".parse::<Name>().expect("domain id"),
        )),
        iroha_model_base::topology::DataSpaceId::UNIVERSAL,
    );
    let domain_id: DomainId = DomainId::try_new("centralbank", "universal").expect("domain id");
    let authority_keypair = checked_torii_test_ed25519_keypair(
        0xab,
        "derive alias resolve account-label fallback authority fixture key",
    );
    let authority = AccountId::new(authority_keypair.public_key().clone());
    let domain = Domain::new(domain_id.clone()).build(&authority);
    let authority_account = Account::new(authority.clone()).build(&authority);
    let world = World::with([domain], [authority_account], []);
    let app = crate::tests_runtime_handlers::native_ingress_app_with_world_for_test(world);
    bind_primary_account_alias_for_test(&app, &authority, &alias_label);
    {
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = app.state.block(header);
        let mut tx = block.transaction();
        let world = tx.world_mut_for_testing();
        world.remove_account_rekey_record_for_testing(&alias_label);
        world
            .account_aliases_mut_for_testing()
            .remove(alias_label.clone());
        if let Some(mut labels) = world
            .account_aliases_by_account_mut_for_testing()
            .get(&authority)
            .cloned()
        {
            labels.remove(&alias_label);
            world
                .account_aliases_by_account_mut_for_testing()
                .insert(authority.clone(), labels);
        }
        tx.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit rekey record removal");
    }
    let request = routing::AliasResolveRequestDto {
        alias: alias.to_string(),
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
async fn alias_resolve_rejects_rekey_record_without_authoritative_binding() {
    let alias = "banking@centralbank.universal";
    let alias_label = iroha_data_model::account::rekey::AccountAlias::new(
        "banking".parse::<Name>().expect("label"),
        Some(iroha_data_model::account::rekey::AccountAliasDomain::new(
            "centralbank".parse::<Name>().expect("domain id"),
        )),
        iroha_model_base::topology::DataSpaceId::UNIVERSAL,
    );
    let authority_keypair = checked_torii_test_ed25519_keypair(
        0xac,
        "derive alias resolve rekey-record fallback authority fixture key",
    );
    let authority = AccountId::new(authority_keypair.public_key().clone());
    let authority_account = Account::new(authority.clone()).build(&authority);
    let app = crate::tests_runtime_handlers::native_ingress_app_with_world_for_test(World::with(
        [
            Domain::new(DomainId::try_new("centralbank", "universal").expect("alias domain"))
                .build(&authority),
        ],
        [authority_account],
        [],
    ));
    {
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = app.state.block(header);
        let mut tx = block.transaction();
        tx.world_mut_for_testing()
            .replace_account_rekey_record_for_testing(
                iroha_data_model::account::rekey::AccountRekeyRecord::new(
                    alias_label.clone(),
                    authority.clone(),
                ),
            );
        tx.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit rekey record");
    }
    let request = routing::AliasResolveRequestDto {
        alias: alias.to_string(),
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
#[cfg(feature = "app_api")]
#[tokio::test]
async fn contract_alias_resolve_returns_not_found_for_unknown_alias() {
    let authority_keypair = checked_torii_test_ed25519_keypair(
        0xad,
        "derive contract alias missing authority fixture key",
    );
    let authority = AccountId::new(authority_keypair.public_key().clone());
    let authority_account = Account::new(authority.clone()).build(&authority);
    let app = crate::tests_runtime_handlers::native_ingress_app_with_world_for_test(World::with(
        [],
        [authority_account],
        [],
    ));
    let request = routing::ContractAliasResolveRequestDto {
        contract_alias: "router::universal".to_string(),
    };
    let body = norito::json::to_vec(&request).expect("encode contract alias request");
    let method = axum::http::Method::POST;
    let uri: axum::http::Uri = "/v1/contracts/aliases/resolve"
        .parse()
        .expect("contract alias resolve URI");
    let headers = crate::tests_runtime_handlers::signed_network_app_headers(
        app.state.network_id_ref(),
        &authority,
        &authority_keypair,
        &method,
        &uri,
        &body,
    );
    let response = handler_contract_alias_resolve(
        State(app),
        method,
        uri,
        headers,
        crate::loopback_connect_info(),
        axum::body::Bytes::from(body),
    )
    .await
    .expect("handler should succeed")
    .into_response();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn contract_alias_resolve_returns_bound_contract() {
    let authority_keypair = checked_torii_test_ed25519_keypair(
        0xae,
        "derive contract alias bound authority fixture key",
    );
    let authority = AccountId::new(authority_keypair.public_key().clone());
    let authority_account = Account::new(authority.clone()).build(&authority);
    let app = crate::tests_runtime_handlers::native_ingress_app_with_world_for_test(World::with(
        [
            Domain::new(DomainId::try_new("dex", "universal").expect("alias domain"))
                .build(&authority),
        ],
        [authority_account],
        [],
    ));
    let contract_address = iroha_data_model::smart_contract::ContractAddress::derive(
        app.state.network_id_ref(),
        &authority,
        0,
        DataSpaceId::UNIVERSAL,
    )
    .expect("contract address");
    bind_contract_alias_for_test(&app, &contract_address, "router::dex.universal");
    let request = routing::ContractAliasResolveRequestDto {
        contract_alias: "router::dex.universal".to_string(),
    };
    let body = norito::json::to_vec(&request).expect("encode contract alias request");
    let method = axum::http::Method::POST;
    let uri: axum::http::Uri = "/v1/contracts/aliases/resolve"
        .parse()
        .expect("contract alias resolve URI");
    let headers = crate::tests_runtime_handlers::signed_network_app_headers(
        app.state.network_id_ref(),
        &authority,
        &authority_keypair,
        &method,
        &uri,
        &body,
    );
    let response = handler_contract_alias_resolve(
        State(app),
        method,
        uri,
        headers,
        crate::loopback_connect_info(),
        axum::body::Bytes::from(body),
    )
    .await
    .expect("handler should succeed")
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .expect("body")
        .to_bytes();
    let value: Value = norito::json::from_slice(&body).expect("contract alias JSON value");
    let object = value.as_object().expect("contract alias response object");
    assert_eq!(
        object.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "contract_alias",
            "contract_address",
            "contract_subject_account",
            "dataspace",
            "contract_alias_binding",
            "source",
        ])
    );
    let binding = object["contract_alias_binding"]
        .as_object()
        .expect("contract alias binding object");
    assert_eq!(
        binding.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        BTreeSet::from(["alias", "bound_at_ms", "status"])
    );
    let dto: routing::ContractAliasResolveResponseDto =
        norito::json::from_slice(&body).expect("json decode");
    assert_eq!(dto.contract_alias, "router::dex.universal");
    assert_eq!(dto.contract_address, contract_address.to_string());
    assert_eq!(
        dto.contract_subject_account,
        contract_address.subject_id().to_string()
    );
    assert_eq!(dto.dataspace, "universal");
    assert_eq!(dto.contract_alias_binding.status, "permanent");
    assert_eq!(dto.source, "world_state");
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn ram_lfe_program_policies_list_registered_hkdf_program() {
    let (app, _, _, _, program) = registered_hkdf_identifier_app(0xb0);
    let response = handler_ram_lfe_program_policies(
        State(app),
        HeaderMap::new(),
        crate::loopback_connect_info(),
    )
    .await
    .expect("list supported program")
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    let dto: routing::RamLfeProgramPolicyListDto = norito::json::from_slice(&body).unwrap();
    assert_eq!(dto.total, 1);
    assert_eq!(dto.items.len(), 1);
    assert_eq!(dto.items[0].program_id, program.program_id.to_string());
    assert_eq!(dto.items[0].backend, "hkdf-sha3-512-prf-v1");
    assert_eq!(dto.items[0].verification_mode, "signed");
    assert!(dto.items[0].active);
    assert!(dto.items[0].input_encryption.is_none());
    assert!(dto.items[0].input_encryption_public_parameters.is_none());
    assert!(dto.items[0].ram_fhe_profile.is_none());
}
#[cfg(feature = "app_api")]
#[test]
fn current_owner_request_dtos_reject_retired_encrypted_fields() {
    for input in [
        r#"{"encrypted_input":"00"}"#,
        r#"{"normalized_input":"a","input_nonce":"a","encrypted_input":"00"}"#,
    ] {
        assert!(norito::json::from_str::<routing::RamLfeExecuteRequestDto>(input).is_err());
    }
    assert!(
        norito::json::from_str::<routing::IdentifierResolveRequestDto>(
            r#"{"policy_id":"phone#retail","encrypted_input":"00","output_opening":{}}"#
        )
        .is_err()
    );
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn ram_lfe_execute_requires_exact_signed_owner_before_evaluation() {
    let (app, owner, _, _, program) = registered_hkdf_identifier_app(0xb2);
    let owner_key = checked_torii_test_ed25519_keypair(0xb2, "actual owner fixture key");
    let uri: axum::http::Uri = format!("/v1/ram-lfe/programs/{}/execute", program.program_id)
        .parse()
        .unwrap();
    let body = br#"{"normalized_input":"alice","input_nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#.to_vec();
    let error = handler_ram_lfe_execute(
        State(app.clone()),
        axum::http::Method::POST,
        uri.clone(),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        AxPath(program.program_id.to_string()),
        body.clone().into(),
    )
    .await
    .expect_err("unsigned request refused");
    assert!(matches!(error, Error::AppUnauthorized { .. }));
    let headers = crate::tests_runtime_handlers::signed_network_app_headers(
        app.state.network_id_ref(),
        &owner,
        &owner_key,
        &axum::http::Method::POST,
        &uri,
        &body,
    );
    let mut changed = body.clone();
    changed.push(b' ');
    assert!(
        handler_ram_lfe_execute(
            State(app.clone()),
            axum::http::Method::POST,
            uri.clone(),
            headers,
            crate::loopback_connect_info(),
            AxPath(program.program_id.to_string()),
            changed.into()
        )
        .await
        .is_err()
    );
    let headers = crate::tests_runtime_handlers::signed_network_app_headers(
        app.state.network_id_ref(),
        &owner,
        &owner_key,
        &axum::http::Method::POST,
        &uri,
        &body,
    );
    let response = handler_ram_lfe_execute(
        State(app),
        axum::http::Method::POST,
        uri,
        headers,
        crate::loopback_connect_info(),
        AxPath(program.program_id.to_string()),
        body.into(),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}
#[cfg(feature = "app_api")]
#[test]
fn ram_lfe_execute_dto_contains_opaque_output_without_a_fabricated_opening() {
    let owner = checked_torii_test_account_id(0xb2, "DTO owner");
    let signer = checked_torii_test_ed25519_keypair(0xb3, "DTO signer");
    let (_, program) = sample_identifier_policy(&owner, &signer, &"string#retail".parse().unwrap());
    let receipt = synthetic_execution_receipt(&program, &signer, 100, Some(200));
    let p = &receipt.payload;
    // Projection of typed synthetic metadata is not private execution or opening.
    let draft = identifier_resolution::RamLfeExecutionDraft {
        output: b"synthetic-output-ciphertext".to_vec(),
        opaque_hash: Hash::new(b"synthetic-opaque"),
        receipt_hash: Hash::new(b"synthetic-receipt"),
        executed_at_ms: p.executed_at_ms,
        expires_at_ms: p.expires_at_ms,
        backend: p.backend,
        output_hash: p.output_hash,
        input_ciphertext_hash: p.input_ciphertext_hash,
        output_ciphertext_hash: p.output_ciphertext_hash,
        associated_data_hash: p.associated_data_hash,
        program_digest: p.program_digest,
        parameter_digest: p.parameter_digest,
        evaluation_key_digest: p.evaluation_key_digest,
        verification_mode: p.verification_mode,
    };
    let dto = ram_lfe_execute_response(&receipt, &draft);
    assert_eq!(dto.program_id, program.program_id.to_string());
    let native_program_frame = norito::encode_canonical(&program.program_id).unwrap();
    assert!(!native_program_frame.is_empty() && native_program_frame.len() <= 4096);
    assert_eq!(
        dto.program_id_canonical,
        hex::encode_upper(&native_program_frame)
    );
    assert_eq!(dto.opaque_output, hex::encode_upper(&draft.output));
    assert_eq!(dto.output_hash, p.output_hash.to_string());
    assert_eq!(dto.receipt.payload.output_hash, dto.output_hash);
    assert_eq!(
        dto.receipt.payload.associated_data_hash,
        dto.associated_data_hash
    );
    assert_eq!(dto.receipt.attestation.kind, "signed");
    assert!(dto.receipt.attestation.signature.is_some());
    let bytes = norito::json::to_vec(&dto).unwrap();
    let raw: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
    let object = raw.as_object().unwrap();
    assert!(!object.contains_key("output_hex"));
    assert!(!object.contains_key("output_opening"));
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn ram_lfe_receipt_verify_rejects_insecure_payload_even_when_output_matches() {
    let (app, _, signer, _, program) = registered_hkdf_identifier_app(0xb4);
    for backend in [RamLfeBackend::BfvAffineV1, RamLfeBackend::BfvProgrammedV1] {
        for mode in [
            RamLfeVerificationMode::Signed,
            RamLfeVerificationMode::Proof,
        ] {
            let mut rejected = program.clone();
            rejected.backend = backend;
            rejected.verification_mode = mode;
            let receipt = synthetic_execution_receipt(&rejected, &signer, 100, None);
            let response = handler_ram_lfe_receipt_verify(
                State(app.clone()),
                HeaderMap::new(),
                crate::loopback_connect_info(),
                NoritoJson(routing::RamLfeReceiptVerifyRequestDto {
                    receipt,
                    output_hex: Some(hex::encode(b"synthetic-output-ciphertext")),
                }),
            )
            .await
            .expect("verification reports refusal")
            .into_response();
            assert_eq!(response.status(), StatusCode::OK);
            let body = http_body_util::BodyExt::collect(response.into_body())
                .await
                .unwrap()
                .to_bytes();
            let dto: routing::RamLfeReceiptVerifyResponseDto =
                norito::json::from_slice(&body).unwrap();
            assert!(!dto.valid);
            assert_eq!(dto.program_id, program.program_id.to_string());
            assert_eq!(dto.backend, backend.as_str());
            assert_eq!(dto.output_hash_matches, Some(true));
            assert!(
                dto.error
                    .as_deref()
                    .unwrap()
                    .contains("noiseless public-key equation")
            );
        }
    }
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn ram_lfe_receipt_verify_rejects_expired_receipt() {
    let (app, _, signer, _, program) = registered_hkdf_identifier_app(0xb6);
    let receipt = synthetic_execution_receipt(&program, &signer, 1, Some(2));
    let response = handler_ram_lfe_receipt_verify(
        State(app),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        NoritoJson(routing::RamLfeReceiptVerifyRequestDto {
            receipt,
            output_hex: None,
        }),
    )
    .await
    .expect("expiry is reported")
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    let dto: routing::RamLfeReceiptVerifyResponseDto = norito::json::from_slice(&body).unwrap();
    assert!(!dto.valid);
    assert!(dto.error.as_deref().unwrap().contains("is expired"));
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn identifier_policies_lists_registered_hkdf_policy() {
    let (app, _, _, policy, _) = registered_hkdf_identifier_app(0x10);
    let response =
        handler_identifier_policies(State(app), HeaderMap::new(), crate::loopback_connect_info())
            .await
            .expect("list registered policy")
            .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    let dto: routing::IdentifierPolicyListDto = norito::json::from_slice(&body).unwrap();
    assert_eq!(dto.total, 1);
    assert_eq!(dto.items.len(), 1);
    assert_eq!(dto.items[0].policy_id, policy.id.to_string());
    assert!(dto.items[0].active);
    assert_eq!(dto.items[0].backend, "hkdf-sha3-512-prf-v1");
    assert_eq!(dto.items[0].normalization, "exact");
    assert!(dto.items[0].input_encryption.is_none());
    assert!(dto.items[0].input_encryption_public_parameters.is_none());
    assert!(dto.items[0].ram_fhe_profile.is_none());
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn identifier_program_registration_rejects_both_diagnostic_bfv_profiles() {
    let owner = checked_torii_test_account_id(0x12, "unavailable program owner");
    let signer = checked_torii_test_ed25519_keypair(0x13, "unavailable program signer");
    let (_, base) = sample_identifier_policy(&owner, &signer, &"string#retail".parse().unwrap());
    let app = mk_app_state_for_tests();
    let mut block = app
        .state
        .block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
    let mut tx = block.transaction();
    for backend in [RamLfeBackend::BfvAffineV1, RamLfeBackend::BfvProgrammedV1] {
        for mode in [
            RamLfeVerificationMode::Signed,
            RamLfeVerificationMode::Proof,
        ] {
            let mut program = base.clone();
            program.backend = backend;
            program.commitment.backend = backend;
            program.commitment.public_parameters = vec![0xff];
            program.verification_mode = mode;
            let error = RegisterRamLfeProgramPolicy { policy: program }
                .execute(&owner, &mut tx)
                .expect_err("neither signed nor proof admission may enable diagnostic BFV");
            assert!(error.to_string().contains("unavailable"), "{error}");
        }
    }
    assert!(
        tx.world
            .ram_lfe_program_policies()
            .get(&base.program_id)
            .is_none()
    );
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn identifier_policies_enforce_token_policy() {
    let mut app = mk_app_state_for_tests();
    {
        let state = Arc::get_mut(&mut app).expect("unique app state");
        state.require_api_token = true;
        state.api_token_digests =
            Arc::new(limits::ApiTokenDigestSet::from_tokens(["token-identifier"]));
    }
    let missing = handler_identifier_policies(
        State(app.clone()),
        HeaderMap::new(),
        crate::loopback_connect_info(),
    )
    .await;
    assert!(matches!(
        missing,
        Err(Error::Query(ValidationFail::NotPermitted(_)))
    ));
    let mut headers = HeaderMap::new();
    headers.insert("x-api-token", HeaderValue::from_static("token-identifier"));
    let response = handler_identifier_policies(State(app), headers, crate::loopback_connect_info())
        .await
        .expect("token accepted")
        .into_response();
    assert_eq!(response.status(), StatusCode::OK);
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn identifier_resolve_requires_signed_policy_owner() {
    let (app, _, _, policy, _) = registered_hkdf_identifier_app(0x14);
    let body = norito::json::to_vec(&routing::IdentifierResolveRequestDto {
        phase: "claim".to_owned(),
        policy_id: policy.id.to_string(),
        normalized_input: "alice".to_owned(),
        input_nonce: "a".repeat(64),
        output_opening: None,
        phone_retail_canonicality: None,
    })
    .expect("encode the current typed owner request");
    let error = handler_identifier_resolve(
        State(app),
        axum::http::Method::POST,
        "/v1/identifiers/resolve".parse().unwrap(),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        body.into(),
    )
    .await
    .expect_err("unsigned current request refused");
    assert!(matches!(error, Error::AppUnauthorized { .. }));
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn identifier_draft_preflight_rejects_bfv_before_input_or_runtime_work() {
    let (app, _, _, policy, base) = registered_hkdf_identifier_app(0x16);
    let resolver = identifier_resolution::IdentifierResolutionService::new();
    for backend in [RamLfeBackend::BfvAffineV1, RamLfeBackend::BfvProgrammedV1] {
        for mode in [
            RamLfeVerificationMode::Signed,
            RamLfeVerificationMode::Proof,
        ] {
            for (policy_backend, commitment_backend) in [
                (backend, backend),
                (backend, RamLfeBackend::HkdfSha3_512PrfV1),
                (RamLfeBackend::HkdfSha3_512PrfV1, backend),
            ] {
                let mut program = base.clone();
                program.backend = policy_backend;
                program.commitment.backend = commitment_backend;
                program.verification_mode = mode;
                let error = derive_identifier_request_draft(
                    &resolver,
                    &policy,
                    &program,
                    &routing::IdentifierResolveRequestDto {
                        policy_id: policy.id.to_string(),
                        phase: "claim".to_owned(),
                        normalized_input: "alice".to_owned(),
                        input_nonce: "not-hex".to_owned(),
                        output_opening: Some(dummy_output_opening_for_access_test()),
                        phone_retail_canonicality: None,
                    },
                    &app.signed_query_admission.network_id(),
                )
                .expect_err("unavailable before parse");
                assert!(
                    identifier_fixture_error_message(&error)
                        .contains("noiseless public-key equation"),
                    "{error}"
                );
                let error = derive_ram_lfe_request_draft(
                    &resolver,
                    &program,
                    &routing::RamLfeExecuteRequestDto {
                        normalized_input: "alice".to_owned(),
                        input_nonce: "not-hex".to_owned(),
                    },
                    app.state.network_id_ref(),
                )
                .expect_err("unavailable before parse");
                assert!(
                    identifier_fixture_error_message(&error)
                        .contains("noiseless public-key equation"),
                    "{error}"
                );
                let response = error.into_response();
                assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
                assert_eq!(
                    response
                        .headers()
                        .get("x-iroha-reject-code")
                        .and_then(|value| value.to_str().ok()),
                    Some("ram_lfe_encryption_unavailable"),
                );
                let body = http_body_util::BodyExt::collect(response.into_body())
                    .await
                    .unwrap()
                    .to_bytes();
                let envelope: ErrorEnvelope = norito::decode_from_bytes(&body).unwrap();
                assert_eq!(envelope.code, "ram_lfe_encryption_unavailable");
                assert!(envelope.message.contains("noiseless public-key equation"));
            }
        }
    }
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn identifier_execution_unsupported_backend_has_typed_availability_error() {
    let response = identifier_execution_error(
        identifier_resolution::IdentifierResolutionError::UnsupportedBackend(
            RamLfeBackend::HkdfSha3_512PrfV1,
        ),
    )
    .into_response();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-reject-code")
            .and_then(|value| value.to_str().ok()),
        Some("ram_lfe_backend_unavailable"),
    );
    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    let envelope: ErrorEnvelope = norito::decode_from_bytes(&body).unwrap();
    assert_eq!(envelope.code, "ram_lfe_backend_unavailable");
    assert_eq!(
        envelope.message,
        "This backend does not support authenticated owner PRF execution."
    );
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn identifier_execution_internal_errors_remain_redacted() {
    let response = identifier_execution_error(
        identifier_resolution::IdentifierResolutionError::Signing("private marker".to_owned()),
    )
    .into_response();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(response.headers().get("x-iroha-reject-code").is_none());
    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    assert!(!String::from_utf8_lossy(&body).contains("private marker"));
    let envelope: ErrorEnvelope = norito::decode_from_bytes(&body).unwrap();
    assert_eq!(envelope.code, "internal_server_error");
    assert_eq!(envelope.message, "Torii could not complete the request.");
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn identifier_receipt_dto_preserves_typed_bindings_without_execution_claim() {
    let (_, owner, signer, policy, program) = registered_hkdf_identifier_app(0x18);
    let execution = synthetic_execution_receipt(&program, &signer, 100, Some(200)).payload;
    let mut opening = dummy_output_opening_for_access_test();
    opening.payload.program_id = program.program_id.clone();
    opening.payload.input_ciphertext_hash = execution.input_ciphertext_hash;
    opening.payload.output_ciphertext_hash = execution.output_ciphertext_hash;
    opening.payload.parameter_digest = execution.parameter_digest;
    opening.payload.evaluation_key_digest = execution.evaluation_key_digest;
    opening.payload.opened_at_ms = execution.executed_at_ms;
    opening.payload.expires_at_ms = execution.expires_at_ms;
    opening.payload.opened_output_hash = Hash::new(b"synthetic-opened-plaintext");
    assert_ne!(
        opening.payload.opened_output_hash,
        execution.output_ciphertext_hash
    );
    opening.signature = SignatureOf::try_new(signer.private_key(), &opening.payload)
        .unwrap()
        .into();
    let payload = iroha_data_model::identifier::IdentifierResolutionReceiptPayload {
        network_id: iroha_data_model::NetworkId::from_genesis_hash(
            iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(
                b"identifier-component-network",
            )),
        ),
        policy_id: policy.id.clone(),
        execution,
        opening,
        opaque_id: iroha_data_model::account::OpaqueAccountId::from(Hash::new(b"synthetic-opaque")),
        receipt_hash: Hash::new(b"synthetic-receipt"),
        uaid: UniversalAccountId::from_hash(Hash::new(b"synthetic-uaid")),
        account_id: owner,
    };
    let receipt = iroha_data_model::identifier::IdentifierResolutionReceipt {
        attestation: iroha_data_model::ram_lfe::RamLfeReceiptAttestation::Signed(
            SignatureOf::try_new(signer.private_key(), &payload)
                .unwrap()
                .into(),
        ),
        payload,
        phone_retail_canonicality: None,
    };
    let dto = identifier_receipt_response(&receipt);
    assert_eq!(dto.payload.policy_id, policy.id.to_string());
    assert_eq!(dto.payload.opaque_id, receipt.payload.opaque_id.to_string());
    assert_eq!(
        dto.payload.receipt_hash,
        receipt.payload.receipt_hash.to_string()
    );
    assert_eq!(dto.payload.uaid, receipt.payload.uaid.to_string());
    assert_eq!(
        dto.payload.account_id,
        receipt.payload.account_id.to_string()
    );
    assert_eq!(
        dto.payload.network_id,
        hex::encode(receipt.payload.network_id.as_bytes())
    );
    assert_eq!(
        dto.payload.opening.payload.program_id,
        receipt.payload.opening.payload.program_id.to_string()
    );
    assert_eq!(
        dto.payload.opening.payload.opened_output_hash,
        receipt
            .payload
            .opening
            .payload
            .opened_output_hash
            .to_string()
    );
    assert_eq!(
        dto.payload.opening.signature,
        hex::encode(receipt.payload.opening.signature.payload())
    );
    assert_eq!(dto.attestation.kind, "signed");
    assert!(!dto.attestation.signature.as_deref().unwrap().is_empty());
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn identifier_owner_nonce_is_exact_lowerhex_nonzero_and_bounded() {
    for nonce in [
        String::new(),
        "a".repeat(63),
        "a".repeat(65),
        "A".repeat(64),
        "0".repeat(64),
        format!("0x{}", "a".repeat(64)),
        "z".repeat(64),
    ] {
        assert!(parse_identifier_input_nonce(&nonce).is_err(), "{nonce}");
    }
    assert_eq!(
        parse_identifier_input_nonce(&"a".repeat(64)).unwrap(),
        [0xaa; 32]
    );
    let (app, owner, _, _, program) = registered_hkdf_identifier_app(0x1a);
    assert!(require_identifier_program_owner(&owner, &program).is_ok());
    assert!(
        require_identifier_program_owner(
            &checked_torii_test_account_id(0x1b, "wrong policy owner"),
            &program
        )
        .is_err()
    );
    for (method, uri, body) in [
        (
            axum::http::Method::GET,
            "/v1/identifiers/resolve",
            vec![b'a'],
        ),
        (
            axum::http::Method::POST,
            "/v1/identifiers/resolve?q=1",
            vec![b'a'],
        ),
        (
            axum::http::Method::POST,
            "/v1/identifiers/resolve",
            vec![b'a'; 16_385],
        ),
    ] {
        assert!(
            authenticate_identifier_owner_request(
                &app,
                &HeaderMap::new(),
                &method,
                &uri.parse().unwrap(),
                &body
            )
            .is_err()
        );
    }
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn identifier_resolve_enforces_token_policy() {
    let mut app = mk_app_state_for_tests();
    {
        let state = Arc::get_mut(&mut app).expect("unique app state");
        state.require_api_token = true;
        state.api_token_digests =
            Arc::new(limits::ApiTokenDigestSet::from_tokens(["token-resolve"]));
    }
    let missing = handler_identifier_resolve(
        State(app),
        axum::http::Method::POST,
        "/v1/identifiers/resolve".parse().unwrap(),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        axum::body::Bytes::from_static(br#"{"phase":"claim","policy_id":"phone#retail","normalized_input":"+6771234567","input_nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#),
    )
    .await;
    assert!(matches!(
        missing,
        Err(Error::Query(ValidationFail::NotPermitted(_)))
    ));
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn identifier_claim_receipt_requires_signed_policy_owner() {
    let (app, owner, _, policy, _) = registered_hkdf_identifier_app(0x1c);
    let body = norito::json::to_vec(&routing::IdentifierResolveRequestDto {
        phase: "prepare".to_owned(),
        policy_id: policy.id.to_string(),
        normalized_input: "alice".to_owned(),
        input_nonce: "a".repeat(64),
        output_opening: None,
        phone_retail_canonicality: None,
    })
    .expect("encode the current typed owner request");
    let uri = format!("/v1/accounts/{owner}/identifiers/claim-receipt")
        .parse()
        .unwrap();
    let error = handler_identifier_claim_receipt(
        State(app),
        axum::http::Method::POST,
        uri,
        HeaderMap::new(),
        crate::loopback_connect_info(),
        AxPath(owner.to_string()),
        body.into(),
    )
    .await
    .expect_err("unsigned prepare refused");
    assert!(matches!(error, Error::AppUnauthorized { .. }));
}
#[cfg(feature = "app_api")]
#[test]
fn identifier_claim_expiry_uses_actual_delivery_time_not_original_opening_time() {
    // Pure record geometry cannot grant an admitted claim or sign a receipt.
    let claim = iroha_data_model::identifier::IdentifierClaimRecord {
        policy_id: "string#retail".parse().unwrap(),
        opaque_id: iroha_data_model::account::OpaqueAccountId::from_hash(Hash::new(
            b"record geometry",
        )),
        receipt_hash: Hash::new(b"receipt geometry"),
        phone_retail_nullifier: None,
        uaid: UniversalAccountId::from_hash(Hash::new(b"uaid geometry")),
        account_id: checked_torii_test_account_id(0x43, "record geometry owner"),
        verified_at_ms: 100,
        expires_at_ms: Some(200),
    };
    assert!(identifier_claim_is_live_at(&claim, 150)); // Original opening was at 150.
    assert!(identifier_claim_is_live_at(&claim, 199));
    assert!(!identifier_claim_is_live_at(&claim, 200));
    assert!(!identifier_claim_is_live_at(&claim, 250)); // Expired after the original opening.
    assert!(!identifier_claim_is_live_at(&claim, 99));
    assert!(!identifier_claim_is_live_at(&claim, 0));
}
#[cfg(feature = "app_api")]
/// Check that the public opening projection preserves every original signed field.
fn assert_identifier_opening_projection(
    actual: &routing::IdentifierOutputOpeningDto,
    original: &iroha_data_model::ram_lfe::RamLfeOutputOpening,
) {
    assert_eq!(actual.signature, hex::encode(original.signature.payload()));
    assert_eq!(
        actual.payload.program_id,
        original.payload.program_id.to_string()
    );
    assert_eq!(
        actual.payload.input_ciphertext_hash,
        original.payload.input_ciphertext_hash.to_string()
    );
    assert_eq!(
        actual.payload.output_ciphertext_hash,
        original.payload.output_ciphertext_hash.to_string()
    );
    assert_eq!(
        actual.payload.parameter_digest,
        original.payload.parameter_digest.to_string()
    );
    assert_eq!(
        actual.payload.evaluation_key_digest,
        original.payload.evaluation_key_digest.to_string()
    );
    assert_eq!(
        actual.payload.opened_output_hash,
        original.payload.opened_output_hash.to_string()
    );
    assert_eq!(actual.payload.opened_at_ms, original.payload.opened_at_ms);
    assert_eq!(actual.payload.expires_at_ms, original.payload.expires_at_ms);
}

#[cfg(feature = "app_api")]
#[tokio::test]
async fn signed_owner_prepare_and_claim_retain_exact_native_opening() {
    let (app, owner, signer, policy, program) = registered_hkdf_identifier_app(0x42);
    let owner_key = checked_torii_test_ed25519_keypair(0x42, "current owner request test key");
    let uri: axum::http::Uri = format!("/v1/accounts/{owner}/identifiers/claim-receipt")
        .parse()
        .unwrap();
    let prepare = routing::IdentifierResolveRequestDto {
        phase: "prepare".to_owned(),
        policy_id: policy.id.to_string(),
        normalized_input: "alice".to_owned(),
        input_nonce: "a".repeat(64),
        output_opening: None,
        phone_retail_canonicality: None,
    };
    let body = norito::json::to_vec(&prepare).unwrap();
    let headers = crate::tests_runtime_handlers::signed_network_app_headers(
        app.state.network_id_ref(),
        &owner,
        &owner_key,
        &axum::http::Method::POST,
        &uri,
        &body,
    );
    let response = handler_identifier_claim_receipt(
        State(app.clone()),
        axum::http::Method::POST,
        uri.clone(),
        headers,
        crate::loopback_connect_info(),
        AxPath(owner.to_string()),
        body.into(),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = http_body_util::BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    let prepared: routing::IdentifierPrfPrepareResponseDto =
        norito::json::from_slice(&bytes).unwrap();
    prepared
        .output_opening
        .verify_signature(signer.public_key())
        .unwrap();
    assert_eq!(prepared.account_id, owner.to_string());
    assert!(prepared.phone_retail_canonicality_payload.is_none());
    let claim = routing::IdentifierResolveRequestDto {
        phase: "claim".to_owned(),
        policy_id: prepare.policy_id.clone(),
        normalized_input: prepare.normalized_input.clone(),
        input_nonce: prepare.input_nonce.clone(),
        output_opening: Some(prepared.output_opening.clone()),
        phone_retail_canonicality: None,
    };
    let body = norito::json::to_vec(&claim).unwrap();
    let headers = crate::tests_runtime_handlers::signed_network_app_headers(
        app.state.network_id_ref(),
        &owner,
        &owner_key,
        &axum::http::Method::POST,
        &uri,
        &body,
    );
    let response = handler_identifier_claim_receipt(
        State(app),
        axum::http::Method::POST,
        uri,
        headers,
        crate::loopback_connect_info(),
        AxPath(owner.to_string()),
        body.into(),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = http_body_util::BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    let receipt: routing::IdentifierResolveResponseDto = norito::json::from_slice(&bytes).unwrap();
    assert_identifier_opening_projection(&receipt.payload.opening, &prepared.output_opening);
    assert_eq!(
        receipt.payload.execution.program_id,
        program.program_id.to_string()
    );
    assert_eq!(
        receipt.payload.execution.executed_at_ms,
        prepared.output_opening.payload.opened_at_ms
    );
    assert_eq!(
        receipt.payload.execution.expires_at_ms,
        prepared.output_opening.payload.expires_at_ms
    );
}

#[cfg(feature = "app_api")]
fn identifier_beneficiary_fixture(
    beneficiary_uaid: bool,
    phone: bool,
) -> (
    SharedAppState,
    AccountId,
    KeyPair,
    AccountId,
    IdentifierPolicy,
) {
    let owner_key = checked_torii_test_ed25519_keypair(0x51, "identifier beneficiary policy owner");
    let owner = AccountId::new(owner_key.public_key().clone());
    let beneficiary = checked_torii_test_account_id(0x52, "identifier receipt beneficiary");
    let other_owner = checked_torii_test_account_id(0x53, "independent identifier policy owner");
    let signer = checked_torii_test_ed25519_keypair(0x54, "identifier beneficiary resolver");
    let owner_account = Account::new(owner.clone())
        .with_uaid(Some(UniversalAccountId::from_hash(Hash::new(
            b"policy-owner-uaid",
        ))))
        .build(&owner);
    let beneficiary_account = Account::new(beneficiary.clone())
        .with_uaid(
            beneficiary_uaid.then(|| UniversalAccountId::from_hash(Hash::new(b"beneficiary-uaid"))),
        )
        .build(&beneficiary);
    let other_account = Account::new(other_owner.clone()).build(&other_owner);
    let domain = Domain::new(DomainId::try_new("directory", "universal").unwrap()).build(&owner);
    let world = World::with(
        [domain],
        [owner_account, beneficiary_account, other_account],
        [],
    );
    let mut app = crate::tests_runtime_handlers::native_ingress_app_with_world_for_test(world);
    let policy_id = if phone {
        "phone#retail"
    } else {
        "string#retail"
    };
    let (mut policy, program) =
        sample_identifier_policy(&owner, &signer, &policy_id.parse().unwrap());
    if phone {
        policy.normalization = IdentifierNormalization::PhoneE164;
        policy = policy.with_phone_retail_attestor_public_key(
            checked_torii_test_ed25519_keypair(0x56, "independent phone beneficiary attestor")
                .public_key()
                .clone(),
        );
    }
    let (other_policy, other_program) =
        sample_identifier_policy(&other_owner, &signer, &"string#other".parse().unwrap());
    let resolver = identifier_resolution::IdentifierResolutionService::new();
    resolver.register_program_runtime(
        program.program_id.clone(),
        iroha_crypto::RamLfeSecret::try_from(b"resolver-secret".to_vec()).unwrap(),
        iroha_crypto::default_bfv_programmed_hidden_program(),
        signer,
        Some(30_000),
    );
    Arc::get_mut(&mut app).unwrap().identifier_resolver = Some(Arc::new(resolver));
    let mut block = app
        .state
        .block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
    let mut tx = block.transaction();
    register_and_activate_identifier_policy_bundle(&owner, &mut tx, &policy, &program);
    register_and_activate_identifier_policy_bundle(
        &other_owner,
        &mut tx,
        &other_policy,
        &other_program,
    );
    tx.apply();
    block.commit_world_overlay_for_testing().unwrap();
    (app, owner, owner_key, beneficiary, policy)
}

#[cfg(feature = "app_api")]
fn identifier_beneficiary_prepare(
    policy: &IdentifierPolicy,
) -> routing::IdentifierResolveRequestDto {
    routing::IdentifierResolveRequestDto {
        phase: "prepare".to_owned(),
        policy_id: policy.id.to_string(),
        normalized_input: if policy.id.is_phone_retail() {
            "+6771234567".to_owned()
        } else {
            "alice".to_owned()
        },
        input_nonce: "a".repeat(64),
        output_opening: None,
        phone_retail_canonicality: None,
    }
}

#[cfg(feature = "app_api")]
async fn identifier_beneficiary_request(
    app: SharedAppState,
    caller: &AccountId,
    key: &KeyPair,
    beneficiary: &AccountId,
    request: &routing::IdentifierResolveRequestDto,
) -> Result<AxResponse, Error> {
    let uri: axum::http::Uri = format!("/v1/accounts/{beneficiary}/identifiers/claim-receipt")
        .parse()
        .unwrap();
    let body = norito::json::to_vec(request).unwrap();
    let headers = crate::tests_runtime_handlers::signed_network_app_headers(
        app.state.network_id_ref(),
        caller,
        key,
        &axum::http::Method::POST,
        &uri,
        &body,
    );
    handler_identifier_claim_receipt(
        State(app),
        axum::http::Method::POST,
        uri,
        headers,
        crate::loopback_connect_info(),
        AxPath(beneficiary.to_string()),
        body.into(),
    )
    .await
}

#[cfg(feature = "app_api")]
#[tokio::test]
async fn signed_identifier_owner_prepares_and_claims_for_distinct_registered_beneficiary() {
    for phone in [false, true] {
        let (app, owner, owner_key, beneficiary, policy) =
            identifier_beneficiary_fixture(true, phone);
        assert_ne!(owner, beneficiary);
        let prepare = identifier_beneficiary_prepare(&policy);
        let response =
            identifier_beneficiary_request(app.clone(), &owner, &owner_key, &beneficiary, &prepare)
                .await
                .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = http_body_util::BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes();
        let prepared: routing::IdentifierPrfPrepareResponseDto =
            norito::json::from_slice(&bytes).unwrap();
        assert_eq!(prepared.account_id, beneficiary.to_string());
        assert_eq!(
            prepared.uaid,
            UniversalAccountId::from_hash(Hash::new(b"beneficiary-uaid")).to_string()
        );
        assert_ne!(
            prepared.uaid,
            UniversalAccountId::from_hash(Hash::new(b"policy-owner-uaid")).to_string()
        );
        assert_eq!(prepared.policy_id, policy.id.to_string());
        assert_eq!(
            prepared.network_id,
            hex::encode(app.state.network_id_ref().as_bytes())
        );
        prepared
            .output_opening
            .verify_signature(
                checked_torii_test_ed25519_keypair(0x54, "identifier beneficiary resolver")
                    .public_key(),
            )
            .unwrap();
        let canonicality = prepared
            .phone_retail_canonicality_payload
            .clone()
            .map(|payload| {
                assert_eq!(payload.account_id, beneficiary);
                assert_eq!(payload.uaid.to_string(), prepared.uaid);
                let key = checked_torii_test_ed25519_keypair(
                    0x56,
                    "independent phone beneficiary attestor",
                );
                let signature = SignatureOf::try_new(key.private_key(), &payload)
                    .unwrap()
                    .into();
                iroha_data_model::identifier::PhoneRetailCanonicalityAttestationV1 {
                    payload,
                    signature,
                }
            });
        assert_eq!(canonicality.is_some(), phone);
        let claim = routing::IdentifierResolveRequestDto {
            phase: "claim".to_owned(),
            policy_id: prepare.policy_id.clone(),
            normalized_input: prepare.normalized_input.clone(),
            input_nonce: prepare.input_nonce.clone(),
            output_opening: Some(prepared.output_opening.clone()),
            phone_retail_canonicality: canonicality.clone(),
        };
        let response =
            identifier_beneficiary_request(app, &owner, &owner_key, &beneficiary, &claim)
                .await
                .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = http_body_util::BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes();
        let receipt: routing::IdentifierResolveResponseDto =
            norito::json::from_slice(&bytes).unwrap();
        assert_eq!(receipt.payload.account_id, beneficiary.to_string());
        assert_eq!(receipt.payload.uaid, prepared.uaid);
        assert_eq!(receipt.payload.network_id, prepared.network_id);
        assert_eq!(receipt.payload.policy_id, prepared.policy_id);
        assert_identifier_opening_projection(&receipt.payload.opening, &prepared.output_opening);
        assert_eq!(
            receipt.payload.execution.executed_at_ms,
            prepared.output_opening.payload.opened_at_ms
        );
        assert_eq!(
            receipt.payload.execution.expires_at_ms,
            prepared.output_opening.payload.expires_at_ms
        );
        assert_eq!(receipt.attestation.kind, "signed");
        assert!(receipt.attestation.signature.is_some());
        assert_eq!(receipt.phone_retail_canonicality, canonicality);
    }
}

#[cfg(feature = "app_api")]
#[tokio::test]
async fn identifier_beneficiary_signature_cannot_replace_policy_owner_authority() {
    let (app, _, _, beneficiary, policy) = identifier_beneficiary_fixture(true, false);
    let key = checked_torii_test_ed25519_keypair(0x52, "identifier receipt beneficiary");
    let error = identifier_beneficiary_request(
        app,
        &beneficiary,
        &key,
        &beneficiary,
        &identifier_beneficiary_prepare(&policy),
    )
    .await
    .expect_err("valid beneficiary signature is not the policy owner");
    assert!(matches!(error, Error::AppUnauthorized { .. }));
}

#[cfg(feature = "app_api")]
#[tokio::test]
async fn signed_identifier_owner_cannot_issue_under_another_owners_policy() {
    let (app, owner, key, beneficiary, policy) = identifier_beneficiary_fixture(true, false);
    let mut request = identifier_beneficiary_prepare(&policy);
    request.policy_id = "string#other".to_owned();
    let error = identifier_beneficiary_request(app, &owner, &key, &beneficiary, &request)
        .await
        .expect_err("another active program and identifier policy retain their owner");
    assert!(matches!(error, Error::AppUnauthorized { .. }));
}

#[cfg(feature = "app_api")]
#[tokio::test]
async fn signed_identifier_owner_requires_registered_beneficiary_with_uaid() {
    for registered in [false, true] {
        let (app, owner, key, beneficiary, policy) = identifier_beneficiary_fixture(false, false);
        let beneficiary = if registered {
            beneficiary
        } else {
            checked_torii_test_account_id(0x55, "unregistered identifier beneficiary")
        };
        let response = identifier_beneficiary_request(
            app,
            &owner,
            &key,
            &beneficiary,
            &identifier_beneficiary_prepare(&policy),
        )
        .await
        .unwrap();
        assert_eq!(
            response.status(),
            if registered {
                StatusCode::CONFLICT
            } else {
                StatusCode::NOT_FOUND
            }
        );
    }
}

#[cfg(feature = "app_api")]
#[tokio::test]
async fn signed_identifier_owner_cannot_retarget_beneficiary_uri_after_signing() {
    let (app, owner, key, beneficiary, policy) = identifier_beneficiary_fixture(true, false);
    let signed_uri: axum::http::Uri = format!("/v1/accounts/{owner}/identifiers/claim-receipt")
        .parse()
        .unwrap();
    let actual_uri: axum::http::Uri =
        format!("/v1/accounts/{beneficiary}/identifiers/claim-receipt")
            .parse()
            .unwrap();
    let body = norito::json::to_vec(&identifier_beneficiary_prepare(&policy)).unwrap();
    let headers = crate::tests_runtime_handlers::signed_network_app_headers(
        app.state.network_id_ref(),
        &owner,
        &key,
        &axum::http::Method::POST,
        &signed_uri,
        &body,
    );
    let error = handler_identifier_claim_receipt(
        State(app),
        axum::http::Method::POST,
        actual_uri,
        headers,
        crate::loopback_connect_info(),
        AxPath(beneficiary.to_string()),
        body.into(),
    )
    .await
    .expect_err("canonical owner signature binds the exact beneficiary path");
    assert!(matches!(error, Error::AppUnauthorized { .. }));
}

#[cfg(feature = "app_api")]
#[tokio::test]
async fn signed_identifier_owner_cannot_replace_phone_attestation_beneficiary() {
    for include_wrong_beneficiary in [false, true] {
        let (app, owner, key, beneficiary, policy) = identifier_beneficiary_fixture(true, true);
        let prepare = identifier_beneficiary_prepare(&policy);
        let response =
            identifier_beneficiary_request(app.clone(), &owner, &key, &beneficiary, &prepare)
                .await
                .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = http_body_util::BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes();
        let prepared: routing::IdentifierPrfPrepareResponseDto =
            norito::json::from_slice(&bytes).unwrap();
        let canonicality = if include_wrong_beneficiary {
            let mut payload = prepared.phone_retail_canonicality_payload.clone().unwrap();
            payload.account_id = owner.clone();
            let attestor =
                checked_torii_test_ed25519_keypair(0x56, "independent phone beneficiary attestor");
            let signature = SignatureOf::try_new(attestor.private_key(), &payload)
                .unwrap()
                .into();
            Some(
                iroha_data_model::identifier::PhoneRetailCanonicalityAttestationV1 {
                    payload,
                    signature,
                },
            )
        } else {
            None
        };
        let claim = routing::IdentifierResolveRequestDto {
            phase: "claim".to_owned(),
            policy_id: prepare.policy_id.clone(),
            normalized_input: prepare.normalized_input.clone(),
            input_nonce: prepare.input_nonce.clone(),
            output_opening: Some(prepared.output_opening),
            phone_retail_canonicality: canonicality,
        };
        let result = identifier_beneficiary_request(app, &owner, &key, &beneficiary, &claim).await;
        assert!(
            result.is_err(),
            "owner authorization cannot replace exact independent phone evidence"
        );
    }
}

#[cfg(feature = "app_api")]
#[tokio::test]
async fn identifier_receipt_lookup_returns_not_found_without_an_admitted_claim() {
    let (app, owner, _, policy, _) = registered_hkdf_identifier_app(0x1e);
    // Projection keeps lookup field coverage without inserting a fabricated
    // claim through a test-only admission bypass.
    let claim = iroha_data_model::identifier::IdentifierClaimRecord {
        policy_id: policy.id.clone(),
        opaque_id: iroha_data_model::account::OpaqueAccountId::from(Hash::new(b"synthetic-opaque")),
        receipt_hash: Hash::new(b"synthetic-receipt"),
        phone_retail_nullifier: None,
        uaid: UniversalAccountId::from_hash(Hash::new(b"synthetic-uaid")),
        account_id: owner,
        verified_at_ms: 100,
        expires_at_ms: Some(200),
    };
    let dto = identifier_claim_lookup_response(&claim);
    assert_eq!(dto.policy_id, policy.id.to_string());
    assert_eq!(dto.opaque_id, claim.opaque_id.to_string());
    assert_eq!(dto.receipt_hash, claim.receipt_hash.to_string());
    assert_eq!(dto.uaid, claim.uaid.to_string());
    assert_eq!(dto.account_id, claim.account_id.to_string());
    assert_eq!(dto.verified_at_ms, 100);
    assert_eq!(dto.expires_at_ms, Some(200));
    let response = handler_identifier_receipt_lookup(
        State(app),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        AxPath(claim.receipt_hash.to_string()),
    )
    .await
    .expect("lookup missing claim")
    .into_response();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn identifier_claim_receipt_enforces_token_policy() {
    let mut app = mk_app_state_for_tests();
    {
        let state = Arc::get_mut(&mut app).expect("unique app state");
        state.require_api_token = true;
        state.api_token_digests = Arc::new(limits::ApiTokenDigestSet::from_tokens(["token-claim"]));
    }
    let missing = handler_identifier_claim_receipt(
        State(app),
        axum::http::Method::POST,
        "/v1/accounts/ed0120deadbeef/identifiers/claim-receipt".parse().unwrap(),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        AxPath("ed0120deadbeef".to_owned()),
        axum::body::Bytes::from_static(br#"{"phase":"claim","policy_id":"phone#retail","normalized_input":"+6771234567","input_nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#),
    )
    .await;
    assert!(matches!(
        missing,
        Err(Error::Query(ValidationFail::NotPermitted(_)))
    ));
}
#[tokio::test]
async fn asset_alias_resolve_returns_definition_fields() {
    let authority =
        checked_torii_test_account_id(0x01, "derive asset alias definition fixture key");
    let domain_id: DomainId = DomainId::try_new("issuer", "universal").expect("domain id");
    let definition_id = AssetDefinitionId::derive_from_components(
        domain_id.clone(),
        Name::from_str("usd").expect("asset name token"),
    );
    let alias: AssetDefinitionAlias = "usd#issuer.universal".parse().expect("asset alias");
    let definition = iroha_data_model::asset::AssetDefinition::numeric(
        definition_id.clone(),
        "usd".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&authority);
    let domain = Domain::new(domain_id.clone()).build(&authority);
    let account = Account::new(authority.clone()).build(&authority);
    let world = World::with([domain], [account], [definition]);
    let app = mk_app_state_for_tests_with_world(world);
    bind_asset_alias_for_test(&app, &authority, &definition_id, &alias, None, 1, 0);
    let response = handler_asset_alias_resolve(
        State(app),
        NoritoJson(routing::AssetAliasResolveRequestDto {
            alias: alias.to_string(),
        }),
    )
    .await
    .expect("handler should succeed")
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .expect("collect body")
        .to_bytes();
    let dto: routing::AssetAliasResolveResponseDto =
        norito::json::from_slice(&body).expect("json decode");
    assert_eq!(dto.alias, "usd#issuer.universal");
    assert!(!dto.asset_definition_id.contains(':'));
    assert_eq!(
        dto.asset_definition_id
            .parse::<AssetDefinitionId>()
            .expect("base58 literal must parse"),
        definition_id
    );
    assert_eq!(dto.asset_name, "usd");
    let alias_binding = dto.alias_binding.expect("alias binding metadata");
    assert_eq!(alias_binding.alias, "usd#issuer.universal");
    assert_eq!(alias_binding.status, "permanent");
    assert_eq!(alias_binding.lease_expiry_ms, None);
    assert_eq!(alias_binding.grace_until_ms, None);
    assert_eq!(dto.source.as_deref(), Some("world_state"));
}
#[tokio::test]
async fn asset_alias_resolve_accepts_short_form_alias() {
    let authority = checked_torii_test_account_id(0x02, "derive short asset alias fixture key");
    let domain_id: DomainId = DomainId::try_new("issuer", "universal").expect("domain id");
    let definition_id = AssetDefinitionId::derive_from_components(
        domain_id.clone(),
        Name::from_str("usd").expect("asset name token"),
    );
    let alias: AssetDefinitionAlias = "usd#universal".parse().expect("asset alias");
    let definition = iroha_data_model::asset::AssetDefinition::numeric(
        definition_id.clone(),
        "usd".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&authority);
    let domain = Domain::new(domain_id.clone()).build(&authority);
    let account = Account::new(authority.clone()).build(&authority);
    let world = World::with([domain], [account], [definition]);
    let app = mk_app_state_for_tests_with_world(world);
    bind_asset_alias_for_test(&app, &authority, &definition_id, &alias, None, 1, 0);
    let response = handler_asset_alias_resolve(
        State(app),
        NoritoJson(routing::AssetAliasResolveRequestDto {
            alias: alias.to_string(),
        }),
    )
    .await
    .expect("handler should succeed")
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .expect("collect body")
        .to_bytes();
    let dto: routing::AssetAliasResolveResponseDto =
        norito::json::from_slice(&body).expect("json decode");
    assert_eq!(dto.alias, "usd#universal");
    assert!(!dto.asset_definition_id.contains(':'));
    assert_eq!(
        dto.asset_definition_id
            .parse::<AssetDefinitionId>()
            .expect("base58 literal must parse"),
        definition_id
    );
    assert_eq!(dto.asset_name, "usd");
    let alias_binding = dto.alias_binding.expect("alias binding metadata");
    assert_eq!(alias_binding.alias, "usd#universal");
    assert_eq!(alias_binding.status, "permanent");
    assert_eq!(dto.source.as_deref(), Some("world_state"));
}
#[tokio::test]
async fn asset_definition_get_returns_full_definition_by_base58_id() {
    let authority = checked_torii_test_account_id(0x03, "derive asset definition get fixture key");
    let domain_id: DomainId = DomainId::try_new("issuer", "universal").expect("domain id");
    let definition_id = AssetDefinitionId::derive_from_components(
        domain_id.clone(),
        Name::from_str("usd").expect("asset name token"),
    );
    let alias: AssetDefinitionAlias = "usd#issuer.universal".parse().expect("asset alias");
    let definition = iroha_data_model::asset::AssetDefinition::numeric(
        definition_id.clone(),
        "usd".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        Some(domain_id.clone()),
    )
    .with_description(Some("Treasury settlement token".to_owned()))
    .build(&authority);
    let domain = Domain::new(domain_id.clone()).build(&authority);
    let account = Account::new(authority.clone()).build(&authority);
    let world = World::with([domain], [account], [definition.clone()]);
    let app = crate::tests_runtime_handlers::native_ingress_app_with_world_for_test(world);
    bind_asset_alias_for_test(&app, &authority, &definition_id, &alias, None, 1, 0);
    let response = handler_asset_definition_get(
        State(app),
        axum::http::Method::GET,
        format!("/v1/assets/definitions/{definition_id}")
            .parse()
            .expect("valid asset definition uri"),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        AxPath(definition_id.to_string()),
    )
    .await
    .expect("handler should succeed")
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .expect("collect body")
        .to_bytes();
    let returned: norito::json::Value = norito::json::from_slice(&body).expect("json decode");
    let definition_id_literal = definition.id().to_string();
    assert_eq!(
        returned["id"].as_str(),
        Some(definition_id_literal.as_str())
    );
    assert_eq!(returned["name"].as_str(), Some(definition.name().as_str()));
    assert_eq!(returned["alias"].as_str(), Some(alias.as_ref()));
    assert_eq!(
        returned["description"].as_str(),
        definition.description().as_deref()
    );
    assert_eq!(
        returned["alias_binding"]["alias"].as_str(),
        Some(alias.as_ref())
    );
    assert_eq!(
        returned["alias_binding"]["status"].as_str(),
        Some("permanent")
    );
}
#[tokio::test]
async fn asset_alias_resolve_returns_not_found_after_grace() {
    let authority = checked_torii_test_account_id(0x04, "derive expired asset alias fixture key");
    let domain_id: DomainId = DomainId::try_new("issuer", "universal").expect("domain id");
    let definition_id = AssetDefinitionId::derive_from_components(
        domain_id.clone(),
        Name::from_str("usd").expect("asset name token"),
    );
    let alias: AssetDefinitionAlias = "usd#issuer.universal".parse().expect("asset alias");
    let definition = iroha_data_model::asset::AssetDefinition::numeric(
        definition_id.clone(),
        "usd".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&authority);
    let domain = Domain::new(domain_id.clone()).build(&authority);
    let account = Account::new(authority.clone()).build(&authority);
    let world = World::with([domain], [account], [definition]);
    let after_grace = 2_000_u64 + 369_u64 * 60 * 60 * 1_000 + 1;
    let app = crate::tests_runtime_handlers::native_ingress_app_with_world_at_time_for_test(
        world,
        after_grace,
    );
    bind_asset_alias_for_test(
        &app,
        &authority,
        &definition_id,
        &alias,
        Some(2_000),
        1,
        1_000,
    );
    let response = handler_asset_alias_resolve(
        State(app),
        NoritoJson(routing::AssetAliasResolveRequestDto {
            alias: alias.to_string(),
        }),
    )
    .await
    .expect("handler should succeed")
    .into_response();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
#[tokio::test]
async fn asset_definition_get_reports_expired_pending_cleanup_status_after_grace() {
    let authority =
        checked_torii_test_account_id(0x05, "derive expired asset definition get fixture key");
    let domain_id: DomainId = DomainId::try_new("issuer", "universal").expect("domain id");
    let definition_id = AssetDefinitionId::derive_from_components(
        domain_id.clone(),
        Name::from_str("usd").expect("asset name token"),
    );
    let alias: AssetDefinitionAlias = "usd#issuer.universal".parse().expect("asset alias");
    let definition = iroha_data_model::asset::AssetDefinition::numeric(
        definition_id.clone(),
        "usd".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        Some(domain_id.clone()),
    )
    .build(&authority);
    let domain = Domain::new(domain_id.clone()).build(&authority);
    let account = Account::new(authority.clone()).build(&authority);
    let world = World::with([domain], [account], [definition]);
    let after_grace = 2_000_u64 + 369_u64 * 60 * 60 * 1_000 + 1;
    let app = crate::tests_runtime_handlers::native_ingress_app_with_world_at_time_for_test(
        world,
        after_grace,
    );
    bind_asset_alias_for_test(
        &app,
        &authority,
        &definition_id,
        &alias,
        Some(2_000),
        1,
        1_000,
    );
    let response = handler_asset_definition_get(
        State(app),
        axum::http::Method::GET,
        format!("/v1/assets/definitions/{definition_id}")
            .parse()
            .expect("valid asset definition uri"),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        AxPath(definition_id.to_string()),
    )
    .await
    .expect("handler should succeed")
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .expect("collect body")
        .to_bytes();
    let dto: norito::json::Value = norito::json::from_slice(&body).expect("json decode");
    assert_eq!(
        dto["alias_binding"]["status"].as_str(),
        Some("expired_pending_cleanup")
    );
    assert_eq!(dto["alias"].as_str(), Some(alias.as_ref()));
}
#[tokio::test]
async fn parse_asset_definition_id_rejects_alias_after_grace() {
    let authority =
        checked_torii_test_account_id(0x06, "derive parse expired asset alias fixture key");
    let domain_id: DomainId = DomainId::try_new("issuer", "universal").expect("domain id");
    let definition_id = AssetDefinitionId::derive_from_components(
        domain_id.clone(),
        Name::from_str("usd").expect("asset name token"),
    );
    let alias: AssetDefinitionAlias = "usd#issuer.universal".parse().expect("asset alias");
    let definition = iroha_data_model::asset::AssetDefinition::numeric(
        definition_id.clone(),
        "usd".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&authority);
    let domain = Domain::new(domain_id.clone()).build(&authority);
    let account = Account::new(authority.clone()).build(&authority);
    let world = World::with([domain], [account], [definition]);
    let after_grace = 2_000_u64 + 369_u64 * 60 * 60 * 1_000 + 1;
    let app = crate::tests_runtime_handlers::native_ingress_app_with_world_at_time_for_test(
        world,
        after_grace,
    );
    bind_asset_alias_for_test(
        &app,
        &authority,
        &definition_id,
        &alias,
        Some(2_000),
        1,
        1_000,
    );
    let error = parse_asset_definition_id(app.as_ref(), alias.as_ref())
        .expect_err("expired alias must stop resolving");
    assert!(matches!(
        error,
        Error::Query(ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::NotFound
        ))
    ));
}
#[tokio::test]
async fn parse_asset_definition_id_accepts_base58_and_alias_literals() {
    let authority = checked_torii_test_account_id(0x07, "derive parse asset alias fixture key");
    let domain_id: DomainId = DomainId::try_new("issuer", "universal").expect("domain id");
    let long_id = AssetDefinitionId::derive_from_components(
        domain_id.clone(),
        Name::from_str("cbdc").expect("asset name token"),
    );
    let short_id = AssetDefinitionId::derive_from_components(
        domain_id.clone(),
        Name::from_str("usd").expect("asset name token"),
    );
    let long_definition = iroha_data_model::asset::AssetDefinition::numeric(
        long_id.clone(),
        "cbdc".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&authority);
    let short_definition = iroha_data_model::asset::AssetDefinition::numeric(
        short_id.clone(),
        "usd".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&authority);
    let domain = Domain::new(domain_id.clone()).build(&authority);
    let account = Account::new(authority.clone()).build(&authority);
    let world = World::with([domain], [account], [long_definition, short_definition]);
    let app = mk_app_state_for_tests_with_world(world);
    bind_asset_alias_for_test(
        &app,
        &authority,
        &long_id,
        &"cbdc#issuer.universal".parse().expect("alias"),
        None,
        1,
        0,
    );
    bind_asset_alias_for_test(
        &app,
        &authority,
        &short_id,
        &"usd#universal".parse().expect("alias"),
        None,
        2,
        0,
    );
    assert_eq!(
        parse_asset_definition_id(app.as_ref(), "cbdc#issuer.universal")
            .expect("long alias should resolve"),
        long_id
    );
    assert_eq!(
        parse_asset_definition_id(app.as_ref(), "usd#universal")
            .expect("short alias should resolve"),
        short_id
    );
    assert_eq!(
        parse_asset_definition_id(app.as_ref(), &long_id.to_string())
            .expect("base58 id should resolve"),
        long_id
    );
    let prefixed_error =
        parse_asset_definition_id(app.as_ref(), "prefix:2f17c72466f84a4bb8a8e24884fdcd2f")
            .expect_err("prefixed literal must be rejected");
    assert!(matches!(
        prefixed_error,
        Error::Query(ValidationFail::TooComplex)
    ));
    let missing_error = parse_asset_definition_id(app.as_ref(), "cbdc#missing")
        .expect_err("unknown alias should be rejected");
    assert!(
        matches!(
            missing_error,
            Error::Query(ValidationFail::QueryFailed(
                iroha_data_model::query::error::QueryExecutionFail::NotFound
            ))
        ),
        "unexpected error: {missing_error:?}"
    );
}
#[tokio::test]
async fn resolve_tx_history_allowed_asset_definition_id_accepts_base58_literal_without_local_definition()
 {
    let authority =
        checked_torii_test_account_id(0x08, "derive tx-history base58 asset fixture key");
    let domain_id: DomainId = DomainId::try_new("issuer", "universal").expect("domain id");
    let expected = AssetDefinitionId::derive_from_components(
        domain_id.clone(),
        Name::from_str("cbdc").expect("asset name token"),
    );
    let domain = Domain::new(domain_id.clone()).build(&authority);
    let account = Account::new(authority.clone()).build(&authority);
    let mut app = mk_app_state_for_tests_with_world(World::with([domain], [account], []));
    let app_state = Arc::get_mut(&mut app).expect("unique app state");
    app_state.tx_history_access_policy = Arc::new(TxHistoryAccessPolicy {
        allowed_asset_definition_id: Some(expected.to_string()),
    });
    assert_eq!(
        resolve_tx_history_allowed_asset_definition_id(app.as_ref())
            .expect("base58 selector should not require local definition"),
        Some(expected)
    );
}
#[tokio::test]
async fn resolve_tx_history_allowed_asset_definition_id_keeps_alias_selectors_strict() {
    let authority =
        checked_torii_test_account_id(0x09, "derive tx-history strict alias fixture key");
    let domain_id: DomainId = DomainId::try_new("issuer", "universal").expect("domain id");
    let domain = Domain::new(domain_id.clone()).build(&authority);
    let account = Account::new(authority.clone()).build(&authority);
    let mut app = mk_app_state_for_tests_with_world(World::with([domain], [account], []));
    let app_state = Arc::get_mut(&mut app).expect("unique app state");
    app_state.tx_history_access_policy = Arc::new(TxHistoryAccessPolicy {
        allowed_asset_definition_id: Some("cbdc#missing".to_owned()),
    });
    let error = resolve_tx_history_allowed_asset_definition_id(app.as_ref())
        .expect_err("unknown alias selector must remain strict");
    assert!(matches!(
        error,
        Error::Query(ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::NotFound
        ))
    ));
}
#[tokio::test]
async fn asset_alias_resolve_returns_not_found_for_unknown_alias() {
    let app = mk_app_state_for_tests();
    let response = handler_asset_alias_resolve(
        State(app),
        NoritoJson(routing::AssetAliasResolveRequestDto {
            alias: "usd#issuer.universal".to_owned(),
        }),
    )
    .await
    .expect("handler should succeed")
    .into_response();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
#[tokio::test]
async fn torii_norito_body_decodes_successful_responses() {
    let record = ProofRecord {
        id: ProofId {
            backend: "debug-proof".to_owned(),
            proof_hash: [0xAA; 32],
        },
        vk_ref: None,
        vk_commitment: None,
        status: ProofStatus::Verified,
        verified_at_height: Some(7),
        bridge: None,
    };
    let response = (StatusCode::OK, utils::NoritoBody(record.clone())).into_response();
    let phase_bytes = 64 * 1_024;
    let mut budget = super::ToriiRoutedReadMemoryBudget::new(
        super::routed_read_working_set_for_phase(phase_bytes),
        phase_bytes,
    )
    .expect("proof record decode budget should fit");
    let decoded =
        super::torii_norito_body::<ProofRecord>(response, "proof record response", &mut budget)
            .await
            .expect("norito body should decode");
    assert_eq!(decoded.value, record);
}
// Route authority comes from the original executed genesis, never lane manifests.
fn native_proof_read_app_for_test(
    nexus: iroha_config::parameters::actual::Nexus,
) -> SharedAppState {
    let app = crate::tests_runtime_handlers::native_ingress_app_with_world_and_nexus_for_test(
        iroha_core::state::World::default(),
        nexus,
    );
    assert_eq!(app.state.view().height(), 1);
    let routes = super::torii_all_dataspace_routes(app.as_ref());
    assert!(!routes.is_empty());
    let mut original = None;
    for route in routes {
        let committee = app
            .state
            .resolve_route_authority(lane_authority_route(route))
            .expect("executed genesis authenticates this configured route");
        assert_eq!(committee.validators().len(), 4);
        assert!(
            committee
                .validators()
                .contains(app.local_peer_id.as_ref().unwrap())
        );
        if let Some(expected) = &original {
            assert_eq!(committee.validators(), expected);
        } else {
            original = Some(committee.validators().to_vec());
        }
    }
    app
}

fn seed_proof_record_after_native_genesis_for_test(
    app: &SharedAppState,
    backend: &str,
    proof_hash: [u8; 32],
) -> String {
    assert_eq!(app.state.view().height(), 1);
    let genesis = app
        .state
        .block_by_height(NonZeroUsize::new(1).unwrap())
        .expect("read original signed genesis through canonical State custody")
        .expect("retain original signed genesis");
    let genesis_hash = genesis.hash();
    let original_route = super::torii_all_dataspace_routes(app.as_ref())[0];
    let original_committee = app
        .state
        .resolve_route_authority(lane_authority_route(original_route))
        .unwrap()
        .validators()
        .to_vec();
    let timestamp = u64::try_from(genesis.header().creation_time().as_millis())
        .unwrap()
        .checked_add(1)
        .unwrap();
    let header = BlockHeader::new(
        NonZeroU64::new(2).unwrap(),
        Some(genesis_hash),
        None,
        timestamp,
        0,
    );
    let id = ProofId {
        backend: backend.to_owned(),
        proof_hash,
    };
    let mut block = app.state.block(header);
    let mut transaction = block.transaction();
    transaction.world.proofs_mut_for_testing().insert(
        id.clone(),
        ProofRecord {
            id: id.clone(),
            vk_ref: None,
            vk_commitment: None,
            status: ProofStatus::Verified,
            verified_at_height: Some(2),
            bridge: None,
        },
    );
    transaction.apply();
    // Only the proof index is synthetic. H1's genuine signed schedule and hash remain intact;
    // this H2 empty-index overlay is not a proof execution or finality claim.
    block
        .commit_empty_block_for_testing()
        .expect("retain exact proof index header and membership");
    assert_eq!(app.state.view().height(), 2);
    assert_eq!(
        app.state
            .block_by_height(NonZeroUsize::new(1).unwrap())
            .expect("reread original signed genesis through canonical State custody")
            .expect("original signed genesis remains retained")
            .hash(),
        genesis_hash
    );
    assert_eq!(
        app.state
            .resolve_route_authority(lane_authority_route(original_route))
            .unwrap()
            .validators(),
        &original_committee
    );
    id.to_string()
}

async fn unavailable_proof_http_upstream_for_test(
    app: &mut SharedAppState,
    route: RoutingDecision,
    proof_id: &str,
) -> (
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
    Arc<std::sync::atomic::AtomicUsize>,
) {
    let committee = app
        .state
        .resolve_route_authority(lane_authority_route(route))
        .expect("unavailable transport must still have genuine configured authority");
    assert_eq!(committee.validators().len(), 4);
    assert!(
        committee
            .validators()
            .contains(app.local_peer_id.as_ref().unwrap())
    );
    let request = torii_read_request(
        ToriiReadEndpointV1::ProofRecordGet,
        ToriiFanoutRouteScopeV1::AllDataspaces,
        route,
        vec![proof_id.to_owned()],
        None,
        Vec::new(),
    );
    let expected_path = torii_external_read_path(&request).unwrap();
    let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = Arc::clone(&requests);
    let router = axum::Router::new().fallback(
        move |method: axum::http::Method, uri: axum::http::Uri, headers: HeaderMap| {
            let expected_path = expected_path.clone();
            let observed = Arc::clone(&observed);
            async move {
                assert_eq!(method, axum::http::Method::GET);
                assert_eq!(uri.path(), expected_path);
                assert_eq!(
                    headers.get(axum::http::header::ACCEPT),
                    Some(&HeaderValue::from_static(crate::utils::NORITO_MIME_TYPE))
                );
                observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                torii_proxy_error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "route_unavailable",
                    "test-owned authoritative HTTP transport is temporarily unavailable",
                )
            }
        },
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .expect("serve test-owned proof transport");
    });
    Arc::get_mut(app).unwrap().public_dataspace_upstreams = Arc::new(
        std::collections::BTreeMap::from([(route.dataspace_id, format!("http://{address}"))]),
    );
    (stop, server, requests)
}

#[tokio::test]
async fn resolve_torii_proof_record_for_routes_fanouts_matching_records() {
    let app = native_proof_read_app_for_test(
        crate::tests_runtime_handlers::private_ingress_nexus_for_test(),
    );
    let id = seed_proof_record_after_native_genesis_for_test(&app, "debug-proof", [0xBC; 32]);
    let routes = super::torii_all_dataspace_routes(app.as_ref());
    let (record, diagnostics, routed_by, _reservation) =
        super::resolve_torii_proof_record_for_routes(&app, routes, id.clone())
            .await
            .expect("proof record fanout should resolve");
    assert_eq!(record.id.to_string(), id);
    assert_eq!(diagnostics.attempted_routes, 3);
    assert_eq!(diagnostics.succeeded_routes, 3);
    assert_eq!(routed_by, "local");
}
#[tokio::test]
async fn resolve_torii_proof_record_for_routes_prefers_not_found_over_route_unavailable_when_missing()
 {
    let mut app = native_proof_read_app_for_test(
        crate::tests_runtime_handlers::private_ingress_with_offline_foreign_nexus_for_test(),
    );
    let local_route = RoutingDecision::new(LaneId::new(1), DataSpaceId::new(10));
    let foreign_route = RoutingDecision::new(LaneId::new(2), DataSpaceId::new(12));
    let missing_id = ProofId {
        backend: "stark/fri/poseidon-x7-goldilocks-6x64-v1-v1".to_owned(),
        proof_hash: [0x44; 32],
    }
    .to_string();
    let (stop, server, requests) =
        unavailable_proof_http_upstream_for_test(&mut app, foreign_route, &missing_id).await;

    for routes in [
        vec![foreign_route, local_route],
        vec![local_route, foreign_route],
    ] {
        let response =
            match super::resolve_torii_proof_record_for_routes(&app, routes, missing_id.clone())
                .await
            {
                Ok(_) => panic!("missing proof record should return an error response"),
                Err(response) => response,
            };
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_ne!(
            response
                .headers()
                .get("x-iroha-reject-code")
                .and_then(|value| value.to_str().ok()),
            Some("route_unavailable"),
            "a definitive missing-proof response should outrank an unrelated unavailable route",
        );
    }
    assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 2);
    stop.send(()).expect("stop proof transport");
    server.await.expect("proof transport finished");
}
#[tokio::test]
async fn resolve_torii_proof_record_for_routes_returns_route_unavailable_when_only_unavailable() {
    let mut app = native_proof_read_app_for_test(
        crate::tests_runtime_handlers::private_ingress_with_offline_foreign_nexus_for_test(),
    );
    let foreign_route = RoutingDecision::new(LaneId::new(2), DataSpaceId::new(12));
    let missing_id = ProofId {
        backend: "stark/fri/poseidon-x7-goldilocks-6x64-v1-v1".to_owned(),
        proof_hash: [0x55; 32],
    }
    .to_string();
    let (stop, server, requests) =
        unavailable_proof_http_upstream_for_test(&mut app, foreign_route, &missing_id).await;

    let response =
        match super::resolve_torii_proof_record_for_routes(&app, vec![foreign_route], missing_id)
            .await
        {
            Ok(_) => panic!("HTTP authoritative route should be unavailable"),
            Err(response) => response,
        };
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-reject-code")
            .and_then(|value| value.to_str().ok()),
        Some("route_unavailable")
    );
    assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 1);
    stop.send(()).expect("stop proof transport");
    server.await.expect("proof transport finished");
}
#[tokio::test]
async fn proof_record_route_preserves_encoded_backend_identity_and_refuses_path_aliases() {
    use tower::ServiceExt as _;
    let app = native_proof_read_app_for_test(iroha_config::parameters::actual::Nexus::default());
    let id = seed_proof_record_after_native_genesis_for_test(&app, "halo2/ipa", [0xAB; 32]);
    let route = *torii_all_dataspace_routes(app.as_ref())
        .first()
        .expect("public route");
    let proxy_path = torii_external_read_path(&torii_read_request(
        ToriiReadEndpointV1::ProofRecordGet,
        ToriiFanoutRouteScopeV1::AllDataspaces,
        route,
        vec![id.clone()],
        None,
        Vec::new(),
    ))
    .expect("actual routed-reader proof path");
    assert!(proxy_path.contains("%3A"));
    let router = axum::Router::new()
        .route(
            route_catalog::pipeline::PROOF.path(),
            axum::routing::get(handler_proof_record_get),
        )
        .with_state(app)
        .layer(axum::Extension(crate::loopback_connect_info()))
        .layer(axum::middleware::from_fn(enforce_strict_request_target));
    let mut url = url::Url::parse("http://localhost/").expect("fixed base URL");
    url.path_segments_mut()
        .expect("base URL")
        .clear()
        .extend(["v1", "proofs", &id]);
    let path = url.path().to_owned();
    for exact_path in [&path, &proxy_path] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(exact_path)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = http_body_util::BodyExt::collect(response.into_body())
            .await
            .expect("body")
            .to_bytes();
        let record: ProofRecord =
            norito::decode_from_bytes(&bytes).expect("canonical proof record");
        assert_eq!(record.id.to_string(), id);
        assert_eq!(record.status, ProofStatus::Verified);
    }
    let missing = ProofId {
        backend: "halo2/ipa".into(),
        proof_hash: [0xCD; 32],
    }
    .to_string();
    url.path_segments_mut()
        .expect("base URL")
        .clear()
        .extend(["v1", "proofs", &missing]);
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(url.path())
                .body(Body::empty())
                .expect("missing request"),
        )
        .await
        .expect("missing response");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    for path in [
        path.replace("%2F", "%2f"),
        path.replace("%2F", "%5C"),
        path.replace("%2F", "%252F"),
        path.replace("%2F", "%2F..%2F"),
        path.replace("%2F", "%2F%2F"),
        format!("{path}/other"),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&path)
                    .header(axum::http::header::ACCEPT, "application/json")
                    .body(Body::empty())
                    .expect("invalid request"),
            )
            .await
            .expect("invalid response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path}");
        let bytes = http_body_util::BodyExt::collect(response.into_body())
            .await
            .expect("error body")
            .to_bytes();
        let error: ErrorEnvelope = norito::json::from_slice(&bytes).expect("typed path refusal");
        assert_eq!(error.code(), "request_path_invalid");
    }
}
#[tokio::test]
async fn proof_record_fanout_requests_the_binary_format_required_by_its_decoder() {
    let app = native_proof_read_app_for_test(iroha_config::parameters::actual::Nexus::default());
    let id = seed_proof_record_after_native_genesis_for_test(&app, "halo2/ipa", [0xD4; 32]);
    let routes = torii_all_dataspace_routes(app.as_ref());
    let route = *routes.first().expect("public route");
    let request = torii_read_request(
        ToriiReadEndpointV1::ProofRecordGet,
        ToriiFanoutRouteScopeV1::AllDataspaces,
        route,
        vec![id.clone()],
        None,
        Vec::new(),
    );
    // Reproduce the incompatible representation without relaxing the shared
    // request default or allowing JSON through the bounded Norito decoder.
    assert_eq!(request.response_format, ToriiProxyResponseFormatV1::Json);
    let response = execute_torii_read_for_route(&app, route, request, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(axum::http::header::CONTENT_TYPE),
        Some(&HeaderValue::from_static("application/json"))
    );
    let mut budget = ToriiRoutedReadMemoryBudget::new(
        app.query_fanout_working_set_bytes,
        app.torii_proxy_max_response_bytes,
    )
    .expect("default bounded query budget");
    let Err(response) =
        torii_norito_body::<ProofRecord>(response, "proof record", &mut budget).await
    else {
        panic!("a JSON route response must not pass the binary decoder");
    };
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert!(torii_response_has_reject_code(
        &response,
        "route_unavailable"
    ));

    // The production fanout must explicitly request the binary representation.
    let (record, diagnostics, _, _reservation) =
        resolve_torii_proof_record_for_routes(&app, routes, id.clone())
            .await
            .unwrap_or_else(|response| panic!("proof fanout failed: {}", response.status()));
    assert_eq!(record.id.to_string(), id);
    assert_eq!(record.status, ProofStatus::Verified);
    assert_eq!(record.verified_at_height, Some(2));
    assert_eq!(record.vk_ref, None);
    assert_eq!(record.vk_commitment, None);
    assert_eq!(record.bridge, None);
    let _ = diagnostics;
}
#[tokio::test]
async fn proof_record_get_advertises_cache_and_304() {
    let app = mk_app_state_for_tests();
    let id = seed_proof_record(&app, "debug-proof", [0xAB; 32]);
    let first = handler_proof_record_get(
        State(app.clone()),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        axum::extract::Path(id.clone()),
    )
    .await
    .expect("proof record ok")
    .into_response();
    assert_eq!(first.status(), StatusCode::OK);
    let etag = first
        .headers()
        .get(axum::http::header::ETAG)
        .cloned()
        .expect("etag header");
    let cache_control = first
        .headers()
        .get(axum::http::header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        cache_control.contains("max-age"),
        "cache header should be present"
    );
    let body = http_body_util::BodyExt::collect(first.into_body())
        .await
        .unwrap()
        .to_bytes();
    assert!(!body.is_empty(), "first response includes body");
    let record = norito::decode_from_bytes::<ProofRecord>(&body).expect("proof record body");
    assert_eq!(record.id.to_string(), id);
    let mut conditional_headers = HeaderMap::new();
    conditional_headers.insert(axum::http::header::IF_NONE_MATCH, etag);
    let not_modified = handler_proof_record_get(
        State(app.clone()),
        conditional_headers,
        crate::loopback_connect_info(),
        axum::extract::Path(id.clone()),
    )
    .await
    .expect("conditional proof ok")
    .into_response();
    assert_eq!(not_modified.status(), StatusCode::NOT_MODIFIED);
    let empty = http_body_util::BodyExt::collect(not_modified.into_body())
        .await
        .unwrap()
        .to_bytes();
    assert!(empty.is_empty(), "304 responses have no body");
    let mut wildcard_headers = HeaderMap::new();
    wildcard_headers.insert(
        axum::http::header::IF_NONE_MATCH,
        axum::http::HeaderValue::from_static("*"),
    );
    let wildcard = handler_proof_record_get(
        State(app.clone()),
        wildcard_headers,
        crate::loopback_connect_info(),
        axum::extract::Path(id),
    )
    .await
    .expect("wildcard conditional proof ok")
    .into_response();
    assert_eq!(wildcard.status(), StatusCode::NOT_MODIFIED);
}
#[tokio::test]
async fn public_proof_record_get_reads_global_protocol_artifacts_across_dataspaces() {
    let app = native_proof_read_app_for_test(
        crate::tests_runtime_handlers::private_ingress_nexus_for_test(),
    );
    let id = seed_proof_record_after_native_genesis_for_test(&app, "debug-proof", [0xCD; 32]);
    let response = handler_proof_record_get(
        State(app.clone()),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        axum::extract::Path(id.clone()),
    )
    .await
    .expect("proof record ok")
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-routed-by")
            .and_then(|value| value.to_str().ok()),
        Some("local")
    );
    assert_eq!(
        response
            .headers()
            .get("x-iroha-fanout-routes-attempted")
            .and_then(|value| value.to_str().ok()),
        Some("3")
    );
    assert_eq!(
        response
            .headers()
            .get("x-iroha-fanout-routes-succeeded")
            .and_then(|value| value.to_str().ok()),
        Some("3")
    );
    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    let record = norito::decode_from_bytes::<ProofRecord>(&body).expect("proof record body");
    assert_eq!(record.id.to_string(), id);
}
#[tokio::test]
async fn proof_record_get_returns_not_found_when_all_routes_miss() {
    let app = native_proof_read_app_for_test(
        crate::tests_runtime_handlers::private_ingress_nexus_for_test(),
    );
    let missing_id = ProofId {
        backend: "stark/fri/poseidon-x7-goldilocks-6x64-v1-v1".to_owned(),
        proof_hash: [0x73; 32],
    }
    .to_string();
    let response = handler_proof_record_get(
        State(app.clone()),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        axum::extract::Path(missing_id),
    )
    .await
    .expect("proof handler should return a response")
    .into_response();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(torii_response_has_reject_code(&response, "not_found"));
    for (header, expected) in [
        ("x-iroha-fanout-routes-attempted", "3"),
        ("x-iroha-fanout-routes-succeeded", "0"),
        ("x-iroha-fanout-routes-not-found", "3"),
    ] {
        assert_eq!(
            response
                .headers()
                .get(header)
                .and_then(|value| value.to_str().ok()),
            Some(expected),
        );
    }
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body bytes");
    let envelope: ErrorEnvelope = norito::decode_from_bytes(&body).expect("error envelope payload");
    // The shared skipped-route collector emits the canonical aggregate absence code.
    assert_eq!(envelope.code, "not_found");
}
#[tokio::test]
async fn proof_retention_status_reports_counts() {
    let mut app = mk_app_state_for_tests();
    let cap = iroha_config::parameters::defaults::zk::proof::RECORD_HISTORY_CAP;
    let grace = iroha_config::parameters::defaults::zk::proof::RETENTION_GRACE_BLOCKS;
    let prune_batch = iroha_config::parameters::defaults::zk::proof::PRUNE_BATCH_SIZE;
    {
        let app_mut = Arc::get_mut(&mut app).expect("unique app");
        let state = Arc::get_mut(&mut app_mut.state).expect("unique core state");
        state
            .edit_zk_for_testing(|zk| zk.proof_history_cap = cap)
            .expect("fixture ZK settings install");
        state
            .edit_zk_for_testing(|zk| zk.proof_retention_grace_blocks = grace)
            .expect("fixture ZK settings install");
        state
            .edit_zk_for_testing(|zk| zk.proof_prune_batch = prune_batch)
            .expect("fixture ZK settings install");
    }
    // Seed one record outside the grace window, one on the boundary, and one fresh record.
    let current_height = grace + 5;
    let stale_height = current_height.saturating_sub(grace + 1);
    let boundary_height = current_height.saturating_sub(grace);
    let fresh_height = current_height;
    {
        let header = BlockHeader::new(NonZeroU64::new(1).expect("height>0"), None, None, 0, 0);
        let mut block = app.state.block(header);
        let mut stx = block.transaction();
        let mut insert_record = |proof_hash: [u8; 32], verified_at_height: u64| -> ProofId {
            let id = ProofId {
                backend: "debug-proof".to_string(),
                proof_hash,
            };
            let rec = ProofRecord {
                id: id.clone(),
                vk_ref: None,
                vk_commitment: None,
                status: ProofStatus::Verified,
                verified_at_height: Some(verified_at_height),
                bridge: None,
            };
            stx.world.proofs_mut_for_testing().insert(id.clone(), rec);
            id
        };
        let _ = insert_record([0xCC; 32], stale_height);
        let _ = insert_record([0xDD; 32], boundary_height);
        let _ = insert_record([0xEE; 32], fresh_height);
        stx.apply();
        block
            .commit_empty_block_for_testing()
            .expect("seed proof block commit should succeed");
    }
    assert!(cap >= 3 && prune_batch >= 2 && grace > 0);
    // At the grace boundary only the stale record expires. One block later the
    // boundary record expires too; status reads must never prune either record.
    for (height, expected_prunable) in [(current_height, 1), (current_height + 1, 2)] {
        set_latest_block_height(&app, height);
        assert_eq!(
            app.state.committed_height(),
            usize::try_from(height).unwrap()
        );
        for media_type in ["application/json", "application/x-norito"] {
            let response = handler_proof_retention_status(
                State(app.clone()),
                HeaderMap::new(),
                crate::loopback_connect_info(),
                Some(crate::utils::extractors::ExtractAccept(
                    HeaderValue::from_static(media_type),
                )),
            )
            .await
            .expect("retention status ok")
            .into_response();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.headers().get(axum::http::header::CONTENT_TYPE),
                Some(&HeaderValue::from_static(media_type))
            );
            let body = http_body_util::BodyExt::collect(response.into_body())
                .await
                .unwrap()
                .to_bytes();
            let status: iroha_torii_shared::ProofRetentionStatus =
                if media_type == "application/json" {
                    norito::json::from_slice(&body).expect("decode JSON retention status")
                } else {
                    norito::decode_from_bytes(&body).expect("decode Norito retention status")
                };
            assert_eq!(status.backends.len(), 1);
            let backend = &status.backends[0];
            assert_eq!(backend.backend, "debug-proof");
            assert_eq!(status.cap_per_backend, cap);
            assert_eq!(status.grace_blocks, grace);
            assert_eq!(status.prune_batch, prune_batch);
            assert_eq!(status.total_records, 3);
            assert_eq!(status.total_prunable, expected_prunable);
            assert_eq!(backend.records, 3);
            assert_eq!(backend.prunable, expected_prunable);
            assert_eq!(backend.oldest_height, Some(stale_height));
            assert_eq!(backend.newest_height, Some(fresh_height));
            assert_eq!(app.state.view().world().proofs().len(), 3);
        }
    }
}
/// Proof retention is committed ZK validity policy: the status route reports the committed
/// values, whatever values this node installed.
#[tokio::test]
async fn proof_retention_status_reports_the_committed_retention_policy() {
    use iroha_data_model::{parameter::Parameter, zk_validity_policy::ZkValidityPolicyV1};
    let mut app = mk_app_state_for_tests();
    let mut policy = ZkValidityPolicyV1::protocol_default();
    policy.proofs.proof_history_cap += 7;
    policy.proofs.proof_retention_grace_blocks += 11;
    policy.proofs.proof_prune_batch += 13;
    policy
        .validate()
        .expect("a policy that differs in retention is valid");
    {
        // The node holds other retention values; they are not what the chain enforces.
        let app_mut = Arc::get_mut(&mut app).expect("unique app");
        let state = Arc::get_mut(&mut app_mut.state).expect("unique core state");
        let mut node = state.installed_zk().clone();
        node.proof_history_cap = 1;
        node.proof_retention_grace_blocks = 1;
        node.proof_prune_batch = 1;
        let ignored = state
            .install_node_zk(node)
            .expect("node ZK resources install");
        assert!(
            ignored
                .iter()
                .any(|field| field.contains("proof_history_cap"))
        );
    }
    {
        // Commit the policy in the first block.
        let header = BlockHeader::new(NonZeroU64::new(1).expect("height>0"), None, None, 0, 0);
        let mut block = app.state.block(header);
        let mut stx = block.transaction();
        stx.world
            .parameters_mut_for_testing()
            .get_mut()
            .set_parameter(Parameter::Custom(policy.clone().into_custom_parameter()))
            .expect("valid fixture parameters");
        stx.apply();
        block
            .commit_empty_block_for_testing()
            .expect("policy block commit should succeed");
    }
    let status =
        crate::routing::handle_proof_retention_status(app.state.clone()).expect("retention status");
    assert_eq!(
        u64::try_from(status.cap_per_backend).expect("fits u64"),
        policy.proofs.proof_history_cap
    );
    assert_eq!(
        status.grace_blocks,
        policy.proofs.proof_retention_grace_blocks
    );
    assert_eq!(
        u64::try_from(status.prune_batch).expect("fits u64"),
        policy.proofs.proof_prune_batch
    );
}
#[cfg(feature = "telemetry")]
#[tokio::test]
async fn axt_proof_cache_debug_reports_snapshot() {
    let mut app = mk_app_state_for_tests();
    let dsid = DataSpaceId::new(9);
    let manifest_root = [0xAA; 32];
    let policy_entries = vec![iroha_data_model::nexus::AxtPolicyBinding {
        dsid,
        policy: iroha_data_model::nexus::AxtPolicyEntry {
            manifest_root,
            target_lane: LaneId::new(2),
            active_handle_era: 10,
            next_handle_counter: 11,
            current_slot: 5,
        },
    }];
    let policy_version = AxtPolicySnapshot::compute_version(&policy_entries);
    {
        let app_mut = Arc::get_mut(&mut app).expect("unique app");
        let state = Arc::get_mut(&mut app_mut.state).expect("unique core state");
        state
            .telemetry
            .set_axt_proof_cache_state(dsid, "miss", manifest_root, 5, Some(10));
        state.telemetry.note_axt_policy_reject(
            LaneId::new(2),
            iroha_data_model::nexus::AxtRejectReason::Manifest,
            77,
        );
        state.telemetry.set_axt_reject_hint(
            dsid,
            LaneId::new(2),
            10,
            11,
            iroha_data_model::nexus::AxtRejectReason::HandleEra,
        );
        state
            .telemetry
            .set_axt_policy_snapshot_version(&AxtPolicySnapshot {
                version: policy_version,
                entries: policy_entries,
            });
    }
    let response = handler_axt_proof_cache_status(
        State(app.clone()),
        HeaderMap::new(),
        axum::extract::ConnectInfo("127.0.0.1:8080".parse().unwrap()),
    )
    .await
    .expect("handler ok")
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    let snapshot: iroha_core::telemetry::AxtDebugStatus =
        norito::json::from_slice(&body).expect("json decode");
    assert_eq!(snapshot.policy_snapshot_version, policy_version);
    assert_eq!(
        snapshot.last_reject.as_ref().map(|reject| reject.reason),
        Some(iroha_data_model::nexus::AxtRejectReason::Manifest)
    );
    assert_eq!(snapshot.hints.len(), 1);
    assert_eq!(
        snapshot.hints[0].reason,
        iroha_data_model::nexus::AxtRejectReason::HandleEra
    );
    assert_eq!(snapshot.cache.len(), 1);
    let entry = &snapshot.cache[0];
    assert_eq!(entry.dataspace, dsid);
    assert_eq!(entry.status, "miss");
    assert_eq!(entry.manifest_root, Some(manifest_root));
    assert_eq!(entry.verified_slot, 5);
    assert_eq!(entry.expiry_slot, Some(10));
}
#[test]
fn axt_reject_query_response_carries_headers() {
    let ctx = AxtRejectContext {
        reason: AxtRejectReason::HandleEra,
        dataspace: Some(DataSpaceId::new(7)),
        lane: Some(LaneId::new(3)),
        snapshot_version: Some(77),
        detail: "handle era differs from the exact active policy era".to_owned(),
        active_handle_era: Some(5),
        next_handle_counter: Some(2),
    };
    let response = Error::Query(ValidationFail::AxtReject(ctx)).into_response();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let headers = response.headers();
    assert_eq!(
        headers
            .get("x-iroha-axt-code")
            .and_then(|v| v.to_str().ok()),
        Some("AXT_HANDLE_ERA")
    );
    assert_eq!(
        headers
            .get("x-iroha-axt-reason")
            .and_then(|v| v.to_str().ok()),
        Some("era")
    );
    assert_eq!(
        headers
            .get("x-iroha-axt-snapshot-version")
            .and_then(|v| v.to_str().ok()),
        Some("77")
    );
    assert_eq!(
        headers
            .get("x-iroha-axt-dataspace")
            .and_then(|v| v.to_str().ok()),
        Some("7")
    );
    assert_eq!(
        headers
            .get("x-iroha-axt-lane")
            .and_then(|v| v.to_str().ok()),
        Some("3")
    );
    assert_eq!(
        headers
            .get("x-iroha-axt-active-handle-era")
            .and_then(|v| v.to_str().ok()),
        Some("5")
    );
    assert_eq!(
        headers
            .get("x-iroha-axt-next-handle-counter")
            .and_then(|v| v.to_str().ok()),
        Some("2")
    );
    let body = executor::block_on(http_body_util::BodyExt::collect(response.into_body()))
        .expect("response body")
        .to_bytes();
    let envelope: ErrorEnvelope = norito::decode_from_bytes(&body).expect("error envelope payload");
    let axt = envelope
        .details
        .and_then(|details| details.axt)
        .expect("axt details");
    assert_eq!(axt.code.as_deref(), Some("AXT_HANDLE_ERA"));
    assert_eq!(axt.dataspace, Some(7));
    assert_eq!(axt.lane, Some(3));
}
#[tokio::test]
async fn proof_get_egress_throttled_returns_retry_after() {
    let mut app = mk_app_state_for_tests();
    let _ = seed_proof_record(&app, "debug-proof", [0xBB; 32]);
    {
        let state = Arc::get_mut(&mut app).expect("unique app");
        state.proof_limits.retry_after = std::time::Duration::from_secs(2);
        state.proof_egress_limiter = limits::RateLimiter::new_u64(Some(1), Some(1));
    }
    let resp = handler_get_proof_by_backend_hash(
        State(app.clone()),
        HeaderMap::new(),
        crate::loopback_connect_info(),
        axum::extract::Path(("debug-proof".to_string(), hex::encode([0xBB; 32]))),
    )
    .await
    .unwrap_or_else(Error::into_response);
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry_after = resp
        .headers()
        .get(axum::http::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert_eq!(retry_after, "2");
}
#[tokio::test]
async fn proof_body_limit_rejects_oversize_body() {
    let mut app = mk_app_state_for_tests();
    {
        let state = Arc::get_mut(&mut app).expect("unique app");
        state.proof_limits.max_body_bytes = 4;
    }
    let err = enforce_proof_body_limit(&app, 16, "v1/zk/verify-batch")
        .expect_err("oversized proof should be rejected");
    match err {
        Error::Query(iroha_data_model::ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::Conversion(msg),
        )) => assert!(
            msg.contains("payload too large"),
            "error message should explain limit"
        ),
        other => panic!("unexpected error: {other:?}"),
    }
}
#[tokio::test]
async fn proof_request_rate_limit_counts_requests_instead_of_body_chunks() {
    let mut app = mk_app_state_for_tests();
    {
        let state = Arc::get_mut(&mut app).expect("unique app state");
        state.proof_rate_limiter = limits::RateLimiter::new(Some(2), Some(60));
    }
    // This was the first permanently unserviceable size under the former
    // 4-KiB chunk cost: floor(245_760 / 4_096) + 1 == 61 > burst 60.
    check_proof_access(
        &app,
        &HeaderMap::new(),
        Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
        "v1/zk/verify-batch",
        PROOF_REQUEST_RATE_COST,
        true,
    )
    .await
    .expect("one maximum-size request must consume one request token");
}
#[tokio::test]
async fn proof_request_rate_limit_admits_max_body_cost_and_throttles_repetition() {
    let mut app = mk_app_state_for_tests();
    {
        let state = Arc::get_mut(&mut app).expect("unique app state");
        state.proof_rate_limiter = limits::RateLimiter::new(Some(1), Some(1));
    }
    let headers = HeaderMap::new();
    let remote = Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    let max_body = app.proof_limits.max_body_bytes;
    enforce_proof_body_limit(&app, max_body, "v1/zk/verify-batch")
        .expect("configured maximum body remains admissible");
    check_proof_access(
        &app,
        &headers,
        remote,
        "v1/zk/verify-batch",
        PROOF_REQUEST_RATE_COST,
        true,
    )
    .await
    .expect("first admissible request should consume one request token");
    let err = check_proof_access(
        &app,
        &headers,
        remote,
        "v1/zk/verify-batch",
        PROOF_REQUEST_RATE_COST,
        true,
    )
    .await
    .expect_err("a repeated request should still be throttled");
    assert!(matches!(
        err,
        Error::ProofRateLimited {
            endpoint: "v1/zk/verify-batch",
            ..
        }
    ));
}

#[test]
fn collection_history_rejects_retired_scoping_and_paging_controls() {
    for query in ["dataspace_id=restricted", "count_mode=bounded", "offset=1"] {
        let error = list_query_from_query_string(Some(query)).expect_err("retired control");
        assert!(matches!(error, Error::CollectionQuery(_)));
    }
}
#[test]
fn asset_transfer_control_read_requires_self_exact_account_grant_or_global_root() {
    let caller = checked_torii_test_account_id(0xe1, "derive control-read caller fixture key");
    let target = checked_torii_test_account_id(0xe2, "derive control-read target fixture key");
    let world = World::with(
        [],
        [
            Account::new(caller.clone()).build(&caller),
            Account::new(target.clone()).build(&target),
        ],
        [],
    );
    let app = mk_app_state_for_tests_with_world(world);
    assert!(can_read_asset_transfer_control(&app, &caller, &caller));
    assert!(!can_read_asset_transfer_control(&app, &caller, &target));

    grant_account_permissions_for_test(
        &app,
        &caller,
        [Permission::from(CanReadRestrictedDataspace {
            dataspace: DataSpaceId::new(10),
        })],
    );
    assert!(
        !can_read_asset_transfer_control(&app, &caller, &target),
        "dataspace-wide read must not expose account-private controls"
    );

    grant_account_permissions_for_test(
        &app,
        &caller,
        [Permission::from(
            iroha_executor_data_model::permission::query::CanReadAccountData {
                account: target.clone(),
            },
        )],
    );
    assert!(can_read_asset_transfer_control(&app, &caller, &target));

    let other =
        checked_torii_test_account_id(0xe3, "derive unrelated control-read target fixture key");
    assert!(!can_read_asset_transfer_control(&app, &caller, &other));
    grant_account_permissions_for_test(&app, &caller, [Permission::from(CanReadAllLedgerData)]);
    assert!(can_read_asset_transfer_control(&app, &caller, &other));
}
