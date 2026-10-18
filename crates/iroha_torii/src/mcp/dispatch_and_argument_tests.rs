// MCP dispatch, route, governance, and argument regressions.

#[test]
fn explorer_history_mcp_query_projection_accepts_only_cursor_contract_fields() {
    let flat = norito::json!({
        "cursor": "Abc_123-xyz",
        "limit": 25,
        "status": "committed",
        "headers": {},
        "accept": "application/json"
    });
    let projected = append_explorer_history_query_arguments(
        "/v1/explorer/transactions".to_owned(),
        flat.as_object().expect("flat arguments"),
        &["cursor", "limit", "status"],
        "transaction history",
    )
    .expect("flat cursor projection");
    assert_eq!(
        projected,
        "/v1/explorer/transactions?cursor=Abc_123-xyz&limit=25&status=committed"
    );

    let nested = norito::json!({ "query": { "limit": 2 } });
    assert_eq!(
        append_explorer_history_query_arguments(
            "/v1/explorer/blocks".to_owned(),
            nested.as_object().expect("nested arguments"),
            &["cursor", "limit"],
            "block history",
        )
        .expect("nested cursor projection"),
        "/v1/explorer/blocks?limit=2"
    );
    for invalid in [
        norito::json!({ "page": 1 }),
        norito::json!({ "offset": 1 }),
        norito::json!({ "query": { "per_page": 10 } }),
        norito::json!({ "query": { "limit": 2 }, "limit": 3 }),
    ] {
        append_explorer_history_query_arguments(
            "/v1/explorer/blocks".to_owned(),
            invalid.as_object().expect("invalid arguments"),
            &["cursor", "limit"],
            "block history",
        )
        .expect_err("retired, unknown, or ambiguous pagination must fail closed");
    }
}

#[test]
fn tool_registry_skips_ws_and_sse_routes() {
    let cfg = iroha_config::parameters::actual::ToriiMcp::default();
    let tools = build_tool_specs(&cfg);
    assert!(!tools.is_empty(), "tool registry must not be empty");
    assert!(tools.iter().all(|tool| match tool.route_backing() {
        Some((_, _, path_template)) => {
            path_template != iroha_torii_shared::route_catalog::streaming::SUBSCRIPTION_WS.path()
                && path_template != iroha_torii_shared::route_catalog::streaming::BLOCKS_WS.path()
                && !path_template.ends_with("/sse")
        }
        None => true,
    }));
    assert!(tools.iter().all(|tool| !tool.name.starts_with("connect.")));
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.connect.session.create")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.connect.ws.ticket")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.connect.session.delete")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.connect.session.status")
    );
    assert!(
        tools
            .iter()
            .all(|tool| tool.name != "iroha.connect.session.create_and_ticket")
    );
    for name in [
        "iroha.accounts.faucet.prepare",
        "iroha.accounts.faucet.submit",
    ] {
        assert!(tools.iter().any(|tool| tool.name == name));
    }
    assert!(tools.iter().any(|tool| tool.name == "iroha.health"));
    assert!(tools.iter().all(|tool| tool.name != "iroha.status"));
    assert!(tools.iter().any(|tool| tool.name == "iroha.parameters.get"));
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.node.capabilities")
    );
    assert!(
        tools
            .iter()
            .all(|tool| tool.name != "iroha.node.query_projection_checkpoint_plan")
    );
    assert!(
        tools
            .iter()
            .all(|tool| tool.name != "iroha.node.query_projection_checkpoint_publish")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.node.query_projection_shard_catalog")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.node.query_projection_checkpoint")
    );
    assert!(tools.iter().all(|tool| tool.name != "iroha.time.now"));
    assert!(tools.iter().all(|tool| tool.name != "iroha.time.status"));
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "torii.get_v1_api_version")
    );
    for retired in [
        "iroha.sumeragi.pacemaker",
        "iroha.sumeragi.commit_certificates",
        "iroha.sumeragi.validator_sets.list",
        "iroha.sumeragi.validator_sets.get",
        "iroha.sumeragi.params",
        "iroha.sumeragi.status",
        "iroha.sumeragi.leader",
        "iroha.sumeragi.qc",
        "iroha.sumeragi.checkpoints",
        "iroha.sumeragi.consensus_keys",
        "iroha.sumeragi.bls_keys",
        "iroha.sumeragi.telemetry",
        "iroha.sumeragi.phases",
        "iroha.sumeragi.commit_qc.get",
        "iroha.sumeragi.evidence.count",
        "iroha.sumeragi.evidence.list",
        "iroha.sumeragi.vrf.penalties",
        "iroha.sumeragi.vrf.epoch",
        "iroha.sumeragi.rbc",
        "iroha.sumeragi.rbc.sessions",
        "iroha.sumeragi.rbc.delivered",
        "iroha.sumeragi.rbc.sample",
        "iroha.sumeragi.collectors",
    ] {
        assert!(
            tools.iter().all(|tool| tool.name != retired),
            "retired MCP tool {retired} leaked"
        );
    }
    assert!(tools.iter().any(|tool| tool.name == "iroha.da.ingest"));
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.da.proof_policies")
    );
    assert!(
        tools
            .iter()
            .all(|tool| tool.name != "iroha.da.proof_policy_snapshot"),
        "duplicate proof-policy MCP tool must remain retired"
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.da.manifests.get")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.da.commitments.list")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.da.commitments.prove")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.da.commitments.verify")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.da.pin_intents.list")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.da.pin_intents.prove")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.da.pin_intents.verify")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.runtime.abi.active")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.runtime.abi.hash")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.runtime.metrics")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.runtime.upgrades.list")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.runtime.upgrades.propose")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.runtime.upgrades.activate")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.runtime.upgrades.cancel")
    );
    assert!(tools.iter().all(|tool| tool.name != "iroha.ledger.headers"));
    assert!(
        tools
            .iter()
            .all(|tool| tool.name != "iroha.ledger.state_root")
    );
    assert!(
        tools
            .iter()
            .all(|tool| tool.name != "iroha.ledger.state_proof")
    );
    assert!(
        tools
            .iter()
            .all(|tool| tool.name != "iroha.ledger.block_proof")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.bridge.finality.proof")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.bridge.finality.bundle")
    );
    assert!(tools.iter().all(|tool| tool.name != "iroha.proofs.get"));
    assert!(tools.iter().any(|tool| tool.name == "iroha.proofs.query"));
    assert!(
        tools
            .iter()
            .all(|tool| tool.name != "iroha.proofs.retention")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.gov.contract.get")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.gov.proposals.deploy_contract")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.gov.proposals.get")
    );
    assert!(tools.iter().any(|tool| tool.name == "iroha.gov.locks.get"));
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.gov.referenda.get")
    );
    assert!(tools.iter().any(|tool| tool.name == "iroha.gov.tally.get"));
    assert!(tools.iter().all(|tool| tool.name != "iroha.gov.ballots.zk"));
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.gov.ballots.zk_v1")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.gov.ballots.zk_v1.ballot_proof")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.gov.ballots.plain")
    );
    for name in [
        "iroha.gov.ballots.zk_v1",
        "iroha.gov.ballots.zk_v1.ballot_proof",
        "iroha.gov.ballots.plain",
    ] {
        let tool = tools
            .iter()
            .find(|tool| tool.name == name)
            .expect("governance ballot tool exists");
        let (effect, _, _) = tool
            .route_backing()
            .expect("governance ballot tool must be route-backed");
        assert_eq!(effect, ToolEffect::Read);
    }
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.gov.protected_namespaces.list")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.gov.protected_namespaces.update")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.gov.unlocks.stats")
    );
    let retired_current_council_tool = ["iroha.gov.", "council.", "current"].concat();
    assert!(
        tools
            .iter()
            .all(|tool| tool.name != retired_current_council_tool.as_str())
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.gov.citizens.count")
    );
    assert!(
        !tools
            .iter()
            .any(|tool| tool.name == "iroha.gov.council.audit")
    );
    assert!(
        !tools
            .iter()
            .any(|tool| tool.name == "iroha.gov.council.derive_vrf")
    );
    assert!(
        !tools
            .iter()
            .any(|tool| tool.name == "iroha.gov.council.persist")
    );
    assert!(
        !tools
            .iter()
            .any(|tool| tool.name == "iroha.gov.council.replace")
    );
    assert!(!tools.iter().any(|tool| tool.name == "iroha.gov.enact"));
    assert!(!tools.iter().any(|tool| tool.name == "iroha.gov.finalize"));
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.aliases.resolve")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.aliases.resolve_index")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.aliases.by_account")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.contracts.code.get")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.contracts.code.bytes.get")
    );
    for retired in [
        "iroha.contracts.deploy",
        "iroha.contracts.deploy_bundle",
        "iroha.contracts.deploy_bundles.get",
    ] {
        assert!(
            tools.iter().all(|tool| tool.name != retired),
            "retired server-side deployment tool leaked into MCP: {retired}"
        );
    }
    assert!(tools.iter().any(|tool| tool.name == "iroha.contracts.call"));
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.contracts.call_and_wait")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.contracts.state.get")
    );
    assert!(tools.iter().any(|tool| tool.name == "iroha.accounts.list"));
    assert!(tools.iter().any(|tool| tool.name == "iroha.accounts.get"));
    assert!(tools.iter().any(|tool| tool.name == "iroha.accounts.qr"));
    assert!(tools.iter().any(|tool| tool.name == "iroha.accounts.query"));
    for name in [
        "iroha.accounts.onboard.prepare",
        "iroha.accounts.onboard.submit",
        "iroha.accounts.faucet.prepare",
        "iroha.accounts.faucet.submit",
    ] {
        assert!(tools.iter().any(|tool| tool.name == name));
    }
    assert!(tools.iter().all(|tool| {
        !matches!(
            tool.name.as_str(),
            "iroha.accounts.onboard" | "iroha.accounts.faucet"
        )
    }));
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.transactions.submit")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.transactions.submit_and_wait")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.transactions.wait")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.accounts.assets")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.accounts.permissions")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.accounts.transactions.query")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.accounts.history")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.accounts.assets.query")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.accounts.portfolio")
    );
    assert!(tools.iter().any(|tool| tool.name == "iroha.domains.list"));
    assert!(tools.iter().any(|tool| tool.name == "iroha.domains.get"));
    assert!(tools.iter().any(|tool| tool.name == "iroha.domains.query"));
    for definition in MUSUBI_V1_TOOL_DEFINITIONS {
        let tool = tools
            .iter()
            .find(|tool| tool.name == definition.name)
            .unwrap_or_else(|| panic!("missing Musubi V1 tool `{}`", definition.name));
        let (effect, method, path_template) = tool
            .route_backing()
            .expect("Musubi V1 tool must be route-backed");
        assert_eq!(method, &Method::POST);
        assert_eq!(path_template, definition.path);
        assert_eq!(effect, definition.effect);
    }
    assert!(!tools.iter().any(|tool| {
        matches!(
            tool.name.as_str(),
            "iroha.musubi.search"
                | "iroha.musubi.release.get"
                | "iroha.musubi.package.releases"
                | "iroha.musubi.package.versions"
                | "iroha.musubi.alias.resolve"
                | "iroha.musubi.instructions.publish_release"
                | "iroha.musubi.instructions.yank_release"
                | "iroha.musubi.instructions.set_alias"
                | "iroha.musubi.instructions.assert_release_exists"
        )
    }));
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.subscriptions.plans.list")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.subscriptions.plans.create")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.subscriptions.list")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.subscriptions.create")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.subscriptions.get")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.subscriptions.pause")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.subscriptions.resume")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.subscriptions.cancel")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.subscriptions.keep")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.subscriptions.usage")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.subscriptions.charge_now")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.assets.definitions")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.assets.definitions.get")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.assets.definitions.query")
    );
    assert!(tools.iter().any(|tool| tool.name == "iroha.assets.holders"));
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.assets.holders.query")
    );
    assert!(tools.iter().any(|tool| tool.name == "iroha.assets.list"));
    assert!(tools.iter().any(|tool| tool.name == "iroha.assets.get"));
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.nfts.chain.list")
    );
    assert!(tools.iter().any(|tool| tool.name == "iroha.nfts.list"));
    assert!(tools.iter().any(|tool| tool.name == "iroha.nfts.get"));
    assert!(tools.iter().any(|tool| tool.name == "iroha.nfts.query"));
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.rwas.chain.list")
    );
    assert!(tools.iter().any(|tool| tool.name == "iroha.rwas.list"));
    assert!(tools.iter().any(|tool| tool.name == "iroha.rwas.get"));
    assert!(tools.iter().any(|tool| tool.name == "iroha.rwas.query"));
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.iso20022.pacs008.submit")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.iso20022.pacs009.submit")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.iso20022.pacs002.submit")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.iso20022.pacs004.submit")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.iso20022.camt056.submit")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.iso20022.sese023.submit")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.iso20022.sese024.submit")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.iso20022.sese025.submit")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.iso20022.colr012.submit")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.iso20022.status.get")
    );
    assert!(tools.iter().any(|tool| tool.name == "iroha.queries.submit"));
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.transactions.list")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.transactions.get")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.instructions.list")
    );
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "iroha.instructions.get")
    );
    assert!(tools.iter().any(|tool| tool.name == "iroha.blocks.list"));
    assert!(tools.iter().any(|tool| tool.name == "iroha.blocks.get"));
}

#[test]
fn faucet_tool_schemas_are_closed_ref_free_exact_envelopes() {
    let cfg = iroha_config::parameters::actual::ToriiMcp::default();
    let tools = build_tool_specs(&cfg);
    for (name, expected_body_fields) in [
        (
            "iroha.accounts.faucet.prepare",
            vec!["schema", "binding", "claim", "fee_payment"],
        ),
        (
            "iroha.accounts.faucet.submit",
            vec![
                "schema",
                "binding",
                "operation",
                "claim",
                "semantic_hash_hex",
                "account_id",
                "asset_definition_id",
                "asset_id",
                "amount",
                "transaction_hash_hex",
                "signed_transaction_wire_hex",
                "signed_transaction_wire_sha256",
                "fee_payment",
                "server_signature",
            ],
        ),
    ] {
        let tool = tools
            .iter()
            .find(|tool| tool.name == name)
            .unwrap_or_else(|| panic!("missing faucet tool {name}"));
        reject_unresolved_schema_refs(&tool.input_schema, name).expect("fully inlined schema");
        let schema = sanitize_tool_input_schema(&tool.input_schema);
        let root = schema.as_object().expect("root object schema");
        assert_eq!(root.get("additionalProperties"), Some(&Value::Bool(false)));
        assert_eq!(
            root.get("required")
                .and_then(Value::as_array)
                .expect("required fields"),
            &[Value::String("body".to_owned())]
        );
        let properties = root
            .get("properties")
            .and_then(Value::as_object)
            .expect("root properties");
        assert!(properties.contains_key("body"));
        assert!(properties.contains_key("accept"));
        assert!(!properties.contains_key("headers"));
        let body = properties
            .get("body")
            .and_then(Value::as_object)
            .expect("body object schema");
        assert_eq!(body.get("additionalProperties"), Some(&Value::Bool(false)));
        let required = body
            .get("required")
            .and_then(Value::as_array)
            .expect("body required fields")
            .iter()
            .filter_map(Value::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(required, expected_body_fields.into_iter().collect());
    }
}
#[test]
fn musubi_mcp_dispatch_requires_a_fresh_exact_target_account_proof() {
    let path = route_catalog::musubi::RELEASE_PUBLISH.path();
    assert_eq!(
        target_extra_header_policy(&Method::POST, path).expect("cataloged Musubi route"),
        ExtraHeaderPolicy::CanonicalAccountAuthentication
    );
    let mut forwarded = HeaderMap::new();
    for (name, value) in [
        (crate::HEADER_ACCOUNT, "outer-account"),
        (crate::HEADER_SIGNATURE, "outer-signature"),
        (crate::HEADER_TIMESTAMP_MS, "1725000000000"),
        (crate::HEADER_NONCE, "outer-nonce"),
    ] {
        forwarded.insert(name, HeaderValue::from_str(value).expect("header"));
    }
    let missing = apply_extra_headers_with_policy(
        &mut forwarded,
        None,
        ExtraHeaderPolicy::CanonicalAccountAuthentication,
    )
    .expect_err("outer MCP authentication must not become the inner Musubi proof");
    assert!(missing.contains("required"));
    assert!(forwarded.is_empty());
    let account_header = test_account_header_hex();
    let incomplete = norito::json!({
        "X-Iroha-Account": (account_header.clone()),
        "X-Iroha-Signature": "AQ=="
    });
    let error = apply_extra_headers_with_policy(
        &mut forwarded,
        Some(&incomplete),
        ExtraHeaderPolicy::CanonicalAccountAuthentication,
    )
    .expect_err("incomplete Musubi target proof must fail before route dispatch");
    assert!(error.contains("complete account/signature/timestamp/nonce tuple"));
    let complete = norito::json!({
        "X-Iroha-Account": account_header,
        "X-Iroha-Signature": "AQ==",
        "X-Iroha-Timestamp-Ms": "1725000000000",
        "X-Iroha-Nonce": "target-nonce"
    });
    apply_extra_headers_with_policy(
        &mut forwarded,
        Some(&complete),
        ExtraHeaderPolicy::CanonicalAccountAuthentication,
    )
    .expect("complete exact-target Musubi proof");
    for name in [
        crate::HEADER_ACCOUNT,
        crate::HEADER_SIGNATURE,
        crate::HEADER_TIMESTAMP_MS,
        crate::HEADER_NONCE,
    ] {
        assert!(forwarded.contains_key(name));
        assert!(forwarded.get(name).expect("target header").is_sensitive());
    }
    assert!(
        target_extra_header_policy(&Method::POST, "/v1/musubi/instructions/publish-release")
            .is_err(),
        "retired Musubi path must never acquire a dispatch authentication policy"
    );
}
#[test]
fn find_tool_spec_by_name_accepts_only_listed_exact_names() {
    let cfg = iroha_config::parameters::actual::ToriiMcp::default();
    let tools = build_tool_specs(&cfg);
    assert!(find_tool_spec_by_name(&tools, "torii.healthCheck").is_none());
    let tool = find_tool_spec_by_name(&tools, "torii.get_health")
        .expect("the exact tools/list name should resolve to the health tool");
    let (_, method, path_template) = tool
        .route_backing()
        .expect("health tool must be route-backed");
    assert_eq!(path_template, "/health");
    assert_eq!(method, &Method::GET);
}
#[test]
fn find_tool_spec_by_name_rejects_removed_post_transaction_alias() {
    let cfg = iroha_config::parameters::actual::ToriiMcp::default();
    let tools = build_tool_specs(&cfg);
    assert!(find_tool_spec_by_name(&tools, "torii.post_transaction").is_none());
    let tool = find_tool_spec_by_name(&tools, "iroha.transactions.submit")
        .expect("canonical transaction submit tool must remain available");
    let (_, method, path_template) = tool
        .route_backing()
        .expect("transaction submit tool must be route-backed");
    assert_eq!(
        path_template,
        iroha_torii_shared::route_catalog::pipeline::TRANSACTION.path()
    );
    assert_eq!(method, &Method::POST);
}
#[tokio::test]
async fn dispatch_route_preserves_inbound_remote_addr_for_internal_allowlist_checks() {
    let mut app = mk_app_state_for_tests();
    let _router_owner = install_remote_addr_probe_router(&mut app);
    let mut inbound_headers = HeaderMap::new();
    inbound_headers.insert(
        HeaderName::from_static(crate::limits::REMOTE_ADDR_HEADER),
        HeaderValue::from_static("198.51.100.23"),
    );
    let result = dispatch_route(
        &app,
        &inbound_headers,
        Method::GET,
        iroha_torii_shared::route_catalog::core::HEALTH.path(),
        None,
        Vec::new(),
        None,
        None,
    )
    .await
    .expect("dispatch succeeds");
    assert_eq!(result.get("status").and_then(Value::as_u64), Some(200));
    let body = result
        .get("body")
        .and_then(Value::as_object)
        .expect("response body");
    assert_eq!(
        body.get("allowed_header_only").and_then(Value::as_bool),
        Some(false)
    );
    assert_eq!(
        body.get("allowed_with_remote").and_then(Value::as_bool),
        Some(false)
    );
    assert_eq!(
        body.get("remote").and_then(Value::as_str),
        Some("198.51.100.23")
    );
    assert_eq!(
        body.get("header").and_then(Value::as_str),
        Some("198.51.100.23")
    );
}
#[tokio::test]
async fn governance_mcp_rejects_noncanonical_ids_before_inner_dispatch() {
    let mut app = mk_app_state_for_tests();
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let _router_owner = install_request_counting_router(&mut app, std::sync::Arc::clone(&calls));
    let headers = HeaderMap::new();
    let proposal = norito::json!({ "path": { "id": ("AA".repeat(32)) } });
    dispatch_iroha_gov_proposals_get(
        &app,
        &headers,
        proposal.as_object().expect("proposal arguments"),
    )
    .await
    .expect_err("uppercase proposal id must fail before routing");
    let locks = norito::json!({ "path": { "rid": "referendum/alias" } });
    dispatch_iroha_gov_locks_get(&app, &headers, locks.as_object().expect("lock arguments"))
        .await
        .expect_err("aliased lock selector must fail before routing");
    let referendum = norito::json!({ "path": { "id": ".hidden" } });
    dispatch_iroha_gov_referenda_get(
        &app,
        &headers,
        referendum.as_object().expect("referendum arguments"),
    )
    .await
    .expect_err("hidden referendum selector must fail before routing");
    let tally = norito::json!({ "path": { "id": "tally%2Falias" } });
    dispatch_iroha_gov_tally_get(&app, &headers, tally.as_object().expect("tally arguments"))
        .await
        .expect_err("escaped tally selector must fail before routing");
    let invalid_election = norito::json!({ "body": { "election_id": "vote/alias" } });
    for result in [
        dispatch_iroha_gov_ballots_zk_v1(
            &app,
            &headers,
            invalid_election.as_object().expect("ZK ballot arguments"),
        )
        .await,
        dispatch_iroha_gov_ballots_zk_v1_ballot_proof(
            &app,
            &headers,
            invalid_election
                .as_object()
                .expect("ZK proof ballot arguments"),
        )
        .await,
    ] {
        result.expect_err("invalid election selector must fail before routing");
    }
    let plain = norito::json!({ "body": { "referendum_id": "vote alias" } });
    dispatch_iroha_gov_ballots_plain(
        &app,
        &headers,
        plain.as_object().expect("plain ballot arguments"),
    )
    .await
    .expect_err("invalid plain selector must fail before routing");
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "invalid governance tool calls must not reach the inner Torii router"
    );
}
#[tokio::test]
async fn openapi_governance_mcp_rejects_noncanonical_ids_before_inner_dispatch() {
    let mut app = mk_app_state_for_tests();
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let _router_owner = install_request_counting_router(&mut app, std::sync::Arc::clone(&calls));
    let headers = HeaderMap::new();
    for (path, arguments) in [
        (
            "/v1/gov/proposals/{id}",
            norito::json!({ "path": { "id": ("AA".repeat(32)) } }),
        ),
        (
            "/v1/gov/locks/{rid}",
            norito::json!({ "path": { "rid": "referendum/alias" } }),
        ),
        (
            "/v1/gov/referenda/{id}",
            norito::json!({ "path": { "id": ".hidden" } }),
        ),
        (
            "/v1/gov/tally/{id}",
            norito::json!({ "path": { "id": "tally%2Falias" } }),
        ),
    ] {
        let tool = sample_tool_at("torii.test", Method::GET, path, ToolEffect::Read);
        dispatch_openapi_tool(
            &app,
            &headers,
            &tool,
            arguments.as_object().expect("GET arguments"),
        )
        .await
        .unwrap_err();
    }
    for (path, arguments) in [
        (
            "/v1/zk/vote/tally",
            norito::json!({ "body": { "election_id": "vote/alias" } }),
        ),
        (
            "/v1/gov/ballots/zk-v1",
            norito::json!({ "body": { "election_id": "vote alias" } }),
        ),
        (
            "/v1/gov/ballots/zk-v1/ballot-proof",
            norito::json!({ "body": { "election_id": "投票" } }),
        ),
        (
            "/v1/gov/ballots/plain",
            norito::json!({ "body": { "referendum_id": ".hidden" } }),
        ),
    ] {
        let tool = sample_tool_at("torii.test", Method::POST, path, ToolEffect::Write);
        dispatch_openapi_tool(
            &app,
            &headers,
            &tool,
            arguments.as_object().expect("POST arguments"),
        )
        .await
        .unwrap_err();
    }
    let opaque = norito::json!({
        "body": { "election_id": "valid-election" },
        "body_base64": "YQ=="
    });
    let tool = sample_tool_at(
        "torii.test",
        Method::POST,
        "/v1/gov/ballots/zk-v1",
        ToolEffect::Write,
    );
    dispatch_openapi_tool(
        &app,
        &headers,
        &tool,
        opaque.as_object().expect("opaque arguments"),
    )
    .await
    .expect_err("opaque body must not bypass identifier preflight");
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "invalid OpenAPI-derived governance calls must not reach the inner Torii router"
    );
}
#[tokio::test]
async fn canonical_governance_mcp_ids_reach_inner_dispatch_once_per_call() {
    let mut app = mk_app_state_for_tests();
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let _router_owner = install_request_counting_router(&mut app, std::sync::Arc::clone(&calls));
    let headers = HeaderMap::new();
    let proposal_id = "ab".repeat(32);
    let maximum_selector = "a".repeat(128);
    let network_id = format!("hash:{}#0000", "A".repeat(64));
    let authority = "sorau-test-authority";
    let target_headers = norito::json!({
        "X-Iroha-Witness": (canonical_test_witness_header())
    });
    let with_target_headers = |mut arguments: Value| {
        arguments
            .as_object_mut()
            .expect("governance arguments")
            .insert("headers".to_owned(), target_headers.clone());
        arguments
    };
    let proposal = with_target_headers(norito::json!({
        "path": { "id": (proposal_id.clone()) }
    }));
    dispatch_iroha_gov_proposals_get(
        &app,
        &headers,
        proposal.as_object().expect("proposal arguments"),
    )
    .await
    .expect("canonical proposal GET dispatches");
    let locks = with_target_headers(norito::json!({ "path": { "rid": "a" } }));
    dispatch_iroha_gov_locks_get(&app, &headers, locks.as_object().expect("lock arguments"))
        .await
        .expect("one-byte lock selector dispatches");
    let referendum = with_target_headers(norito::json!({
        "path": { "id": (maximum_selector.clone()) }
    }));
    dispatch_iroha_gov_referenda_get(
        &app,
        &headers,
        referendum.as_object().expect("referendum arguments"),
    )
    .await
    .expect("128-byte referendum selector dispatches");
    let tally = with_target_headers(norito::json!({
        "path": { "id": "A9_selector~with.dots" }
    }));
    dispatch_iroha_gov_tally_get(&app, &headers, tally.as_object().expect("tally arguments"))
        .await
        .expect("canonical tally selector dispatches");
    let zk = with_target_headers(norito::json!({
        "body": {
            "network_id": (network_id.clone()),
            "authority": authority,
            "election_id": "election-1",
            "backend": "halo2/ipa",
            "envelope_b64": "AQ=="
        }
    }));
    dispatch_iroha_gov_ballots_zk_v1(&app, &headers, zk.as_object().expect("ZK ballot arguments"))
        .await
        .expect("canonical ZK selector dispatches");
    let zk_proof = with_target_headers(norito::json!({
        "body": {
            "network_id": (network_id.clone()),
            "authority": authority,
            "election_id": (maximum_selector.clone()),
            "ballot": {
                "backend": "halo2/ipa",
                "envelope_bytes": "AQ=="
            }
        }
    }));
    dispatch_iroha_gov_ballots_zk_v1_ballot_proof(
        &app,
        &headers,
        zk_proof.as_object().expect("ZK proof arguments"),
    )
    .await
    .expect("canonical ZK proof selector dispatches");
    let plain = with_target_headers(norito::json!({
        "body": {
            "network_id": network_id,
            "authority": authority,
            "referendum_id": "referendum-1",
            "owner": authority,
            "amount": "100",
            "duration_blocks": "600",
            "direction": "Aye"
        }
    }));
    dispatch_iroha_gov_ballots_plain(
        &app,
        &headers,
        plain.as_object().expect("plain ballot arguments"),
    )
    .await
    .expect("canonical plain selector dispatches");
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        7,
        "each canonical purpose-built governance call must dispatch exactly once"
    );
    calls.store(0, std::sync::atomic::Ordering::SeqCst);
    for (path, arguments) in [
        (
            "/v1/gov/proposals/{id}",
            with_target_headers(norito::json!({
                "path": { "id": (proposal_id.clone()) }
            })),
        ),
        (
            "/v1/gov/locks/{rid}",
            with_target_headers(norito::json!({ "path": { "rid": "a" } })),
        ),
        (
            "/v1/gov/referenda/{id}",
            with_target_headers(norito::json!({
                "path": { "id": (maximum_selector.clone()) }
            })),
        ),
        (
            "/v1/gov/tally/{id}",
            with_target_headers(norito::json!({
                "path": { "id": "A9_selector~with.dots" }
            })),
        ),
    ] {
        let tool = sample_tool_at("torii.test", Method::GET, path, ToolEffect::Read);
        dispatch_openapi_tool(
            &app,
            &headers,
            &tool,
            arguments.as_object().expect("OpenAPI GET arguments"),
        )
        .await
        .expect("canonical OpenAPI-derived GET dispatches");
    }
    for (path, arguments) in [
        (
            "/v1/zk/vote/tally",
            with_target_headers(norito::json!({ "body": { "election_id": "a" } })),
        ),
        (
            "/v1/gov/ballots/zk-v1",
            with_target_headers(norito::json!({
                "body": { "election_id": "election-1" }
            })),
        ),
        (
            "/v1/gov/ballots/zk-v1/ballot-proof",
            with_target_headers(norito::json!({
                "body": { "election_id": (maximum_selector.clone()) }
            })),
        ),
        (
            "/v1/gov/ballots/plain",
            with_target_headers(norito::json!({
                "body": { "referendum_id": "referendum-1" }
            })),
        ),
    ] {
        let tool = sample_tool_at("torii.test", Method::POST, path, ToolEffect::Write);
        dispatch_openapi_tool(
            &app,
            &headers,
            &tool,
            arguments.as_object().expect("OpenAPI POST arguments"),
        )
        .await
        .expect("canonical OpenAPI-derived POST dispatches");
    }
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        8,
        "each canonical OpenAPI-derived governance call must dispatch exactly once"
    );
}
#[tokio::test]
async fn dispatch_route_blocks_remote_addr_spoofing_from_extra_headers() {
    let mut app = mk_app_state_for_tests();
    let _router_owner = install_remote_addr_probe_router(&mut app);
    let mut extra_headers = Map::new();
    extra_headers.insert(
        crate::limits::REMOTE_ADDR_HEADER.to_owned(),
        Value::String("127.0.0.1".to_owned()),
    );
    let extra_headers = Value::Object(extra_headers);
    let result = dispatch_route(
        &app,
        &HeaderMap::new(),
        Method::GET,
        iroha_torii_shared::route_catalog::core::HEALTH.path(),
        Some(&extra_headers),
        Vec::new(),
        None,
        None,
    )
    .await
    .expect("dispatch succeeds");
    assert_eq!(result.get("status").and_then(Value::as_u64), Some(200));
    let body = result
        .get("body")
        .and_then(Value::as_object)
        .expect("response body");
    assert_eq!(
        body.get("allowed_header_only").and_then(Value::as_bool),
        Some(false)
    );
    assert_eq!(
        body.get("allowed_with_remote").and_then(Value::as_bool),
        Some(false)
    );
    assert_eq!(body.get("remote").and_then(Value::as_str), Some("0.0.0.0"));
    assert!(body.get("header").is_some_and(Value::is_null));
}
#[tokio::test]
async fn dispatch_route_fails_closed_when_required_api_tokens_are_unconfigured() {
    let mut app = mk_app_state_for_tests();
    let _router_owner = install_api_token_probe_router(&mut app, &[]);
    let result = dispatch_route(
        &app,
        &HeaderMap::new(),
        Method::GET,
        iroha_torii_shared::route_catalog::core::HEALTH.path(),
        None,
        Vec::new(),
        None,
        None,
    )
    .await
    .expect("inner router returns the authentication response");
    assert_eq!(result.get("status").and_then(Value::as_u64), Some(503));
}
#[tokio::test]
async fn dispatch_route_extra_headers_cannot_inject_an_api_token() {
    let mut app = mk_app_state_for_tests();
    let _router_owner = install_api_token_probe_router(&mut app, &["configured-token"]);
    let extra_headers = norito::json!({
        "x-api-token": "configured-token"
    });
    let rejected = dispatch_route(
        &app,
        &HeaderMap::new(),
        Method::GET,
        iroha_torii_shared::route_catalog::core::HEALTH.path(),
        Some(&extra_headers),
        Vec::new(),
        None,
        None,
    )
    .await
    .expect("inner router returns the authentication response");
    assert_eq!(rejected.get("status").and_then(Value::as_u64), Some(401));
    let mut inbound = HeaderMap::new();
    inbound.insert(
        HEADER_X_API_TOKEN,
        HeaderValue::from_static("configured-token"),
    );
    let accepted = dispatch_route(
        &app,
        &inbound,
        Method::GET,
        iroha_torii_shared::route_catalog::core::HEALTH.path(),
        None,
        Vec::new(),
        None,
        None,
    )
    .await
    .expect("single trusted outer token dispatches");
    assert_eq!(accepted.get("status").and_then(Value::as_u64), Some(204));
}
#[test]
fn fill_path_template_substitutes_required_values() {
    let args = norito::json!({
        "sid": "abc",
        "role": "wallet"
    });
    let path = fill_path_template("/v1/connect/session/{sid}/{role}", Some(&args)).expect("filled");
    assert_eq!(path, "/v1/connect/session/abc/wallet");
}
#[test]
fn fill_path_template_percent_encodes_without_accepting_composites() {
    let args = norito::json!({ "value": "a b/+~" });
    assert_eq!(
        fill_path_template("/v1/items/{value}", Some(&args)).expect("encoded path"),
        "/v1/items/a%20b%2F%2B~"
    );
    let composite = norito::json!({ "value": { "nested": true } });
    fill_path_template("/v1/items/{value}", Some(&composite))
        .expect_err("composite path values must fail closed");
}
#[test]
fn ws_ticket_uses_ws_url_and_protocol_token() {
    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, HeaderValue::from_static("node.example"));
    let token = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
    let args = norito::json!({
        "sid": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
        "role": "app",
        "token": token,
        "node_url": "https://trusted.example"
    });
    let ticket =
        build_connect_ws_ticket(args.as_object().expect("object"), &headers).expect("ticket");
    let ws_url = ticket
        .get("ws_url")
        .and_then(Value::as_str)
        .expect("ws url");
    assert!(ws_url.starts_with("wss://trusted.example/v1/connect/ws?"));
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token.as_bytes());
    assert_eq!(
        ticket
            .get("sec_websocket_protocol")
            .and_then(Value::as_str)
            .expect("protocol"),
        format!("iroha-connect.token.v1.{encoded}")
    );
}
#[test]
fn ws_ticket_accepts_role_specific_token_aliases() {
    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, HeaderValue::from_static("node.example"));
    let args = norito::json!({
        "sid": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
        "role": "wallet",
        "token_wallet": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI",
        "node_url": "https://node.example"
    });
    let ticket =
        build_connect_ws_ticket(args.as_object().expect("object"), &headers).expect("ticket");
    assert_eq!(
        ticket
            .get("authorization_header")
            .and_then(Value::as_str)
            .expect("authorization"),
        "Bearer AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI"
    );
}
#[test]
fn ws_ticket_schema_requires_a_token_for_the_selected_role() {
    let tool = iroha_connect_ws_ticket_tool();
    let schema = sanitize_tool_input_schema(&tool.input_schema);
    let base = norito::json!({
        "sid": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
        "role": "wallet",
        "node_url": "https://node.example"
    });
    assert!(validate_json_schema_value(&schema, &base, "arguments").is_err());

    let mut selected = base.clone();
    selected.as_object_mut().expect("object").insert(
        "token_wallet".into(),
        Value::String("AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI".into()),
    );
    validate_json_schema_value(&schema, &selected, "arguments")
        .expect("selected-role token satisfies the descriptor");

    let mut mismatched = base;
    mismatched.as_object_mut().expect("object").insert(
        "token_app".into(),
        Value::String("AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI".into()),
    );
    assert!(validate_json_schema_value(&schema, &mismatched, "arguments").is_err());
}
#[test]
fn ws_ticket_rejects_noncanonical_or_header_unsafe_tokens() {
    for token in [
        "short",
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE\r\nInjected: yes",
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEextra",
    ] {
        let args = norito::json!({
            "sid": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
            "role": "app",
            "token": token,
            "node_url": "https://node.example"
        });
        build_connect_ws_ticket(args.as_object().expect("object"), &HeaderMap::new())
            .expect_err("noncanonical Connect role token must fail closed");
    }
}
#[test]
fn ws_ticket_rejects_retired_sid_and_node_aliases() {
    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, HeaderValue::from_static("node.example"));
    for retired in [
        norito::json!({
            "session_id": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
            "role": "app",
            "token": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
            "node_url": "https://node.example"
        }),
        norito::json!({
            "path": { "sid": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE" },
            "role": "app",
            "token": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
            "node_url": "https://node.example"
        }),
        norito::json!({
            "sid": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
            "role": "app",
            "token": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
            "node_url": "https://node.example",
            "node": "https://node.example"
        }),
    ] {
        build_connect_ws_ticket(retired.as_object().expect("object"), &headers)
            .expect_err("retired Connect ticket alias must reject");
    }
}
#[test]
fn build_connect_session_create_body_derives_exact_network_sid() {
    let args = norito::json!({
        "network_id": "hash:4141414141414141414141414141414141414141414141414141414141414141#7023",
        "app_pk": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
        "nonce": "AgICAgICAgICAgICAgICAg",
        "node": "https://node.example"
    });
    let body =
        build_connect_session_create_body(args.as_object().expect("object")).expect("create body");
    let payload = body.as_object().expect("object");
    assert_eq!(
        payload.get("sid").and_then(Value::as_str),
        Some("NYWJG9y5e88ugmF2QZQP7dTCwL6UbSG2A8YNvPpX9LI")
    );
    assert_eq!(
        payload.get("network_id").and_then(Value::as_str),
        args.get("network_id").and_then(Value::as_str)
    );
    assert_eq!(
        payload.get("app_pk").and_then(Value::as_str),
        args.get("app_pk").and_then(Value::as_str)
    );
    assert_eq!(
        payload.get("nonce").and_then(Value::as_str),
        args.get("nonce").and_then(Value::as_str)
    );
    assert_eq!(
        payload.get("node").and_then(Value::as_str),
        Some("https://node.example")
    );
}
#[test]
fn build_connect_session_create_body_rejects_retired_identity_inputs() {
    for retired in [
        "sid",
        "session_id",
        "body",
        "chain_id",
        "chainId",
        "node_url",
    ] {
        let mut args = norito::json!({
            "network_id": "hash:4141414141414141414141414141414141414141414141414141414141414141#7023",
            "app_pk": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
            "nonce": "AgICAgICAgICAgICAgICAg"
        });
        args.as_object_mut()
            .expect("object")
            .insert(retired.into(), Value::String("retired".into()));
        let err = build_connect_session_create_body(args.as_object().expect("object"))
            .expect_err("retired Connect create input must reject");
        assert!(
            err.contains("hard cut"),
            "unexpected `{retired}` error: {err}"
        );
    }
}
#[test]
fn build_connect_session_create_body_rejects_missing_or_noncanonical_identity() {
    let valid = || {
        norito::json!({
            "network_id": "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0",
            "app_pk": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
            "nonce": "AgICAgICAgICAgICAgICAg"
        })
    };
    for missing in ["network_id", "app_pk", "nonce"] {
        let mut args = valid();
        args.as_object_mut().expect("object").remove(missing);
        assert!(
            build_connect_session_create_body(args.as_object().expect("object")).is_err(),
            "missing {missing} must reject"
        );
    }
    let mutations = [
        (
            "network_id",
            "hash:32c903e5b3497e34c2b844ebfe8a39c19e6cf8f95d44c1ffb8ba9dcb42f91149#a2f0",
        ),
        ("app_pk", "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="),
        ("app_pk", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        ("nonce", "AgICAgICAgICAgICAgICAg="),
        ("nonce", "AAAAAAAAAAAAAAAAAAAAAA"),
    ];
    for (field, replacement) in mutations {
        let mut args = valid();
        args.as_object_mut()
            .expect("object")
            .insert(field.into(), Value::String(replacement.into()));
        assert!(
            build_connect_session_create_body(args.as_object().expect("object")).is_err(),
            "noncanonical {field} must reject"
        );
    }
}
#[test]
fn connect_session_create_tool_schema_has_only_hard_cut_identity() {
    for tool in [iroha_connect_session_create_tool()] {
        let schema = tool.input_schema.as_object().expect("schema object");
        let required = schema
            .get("required")
            .and_then(Value::as_array)
            .expect("required fields");
        for field in ["network_id", "app_pk", "nonce"] {
            assert!(required.iter().any(|value| value.as_str() == Some(field)));
        }
        let properties = schema
            .get("properties")
            .and_then(Value::as_object)
            .expect("schema properties");
        for retired in [
            "sid",
            "session_id",
            "body",
            "chain_id",
            "chainId",
            "node_url",
        ] {
            assert!(!properties.contains_key(retired));
        }
    }
}
#[test]
fn canonical_connect_sid_argument_accepts_only_exact_sid() {
    let canonical = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
    let args = norito::json!({ "sid": canonical });
    assert_eq!(
        canonical_connect_sid_argument(args.as_object().expect("object")).expect("canonical sid"),
        canonical
    );
    for invalid in [
        norito::json!({ "session_id": canonical }),
        norito::json!({ "path": { "sid": canonical } }),
        norito::json!({ "sid": "AQEBAQ" }),
        norito::json!({ "sid": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=" }),
        norito::json!({ "sid": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }),
    ] {
        canonical_connect_sid_argument(invalid.as_object().expect("object"))
            .expect_err("noncanonical sid must reject");
    }
}
#[test]
fn connect_management_authorization_requires_canonical_token() {
    let token = "A".repeat(43);
    let authorization =
        connect_management_authorization_value(&token).expect("canonical management authorization");
    let expected = format!("Bearer {token}");
    assert_eq!(
        authorization.to_str().expect("ASCII authorization"),
        expected.as_str()
    );
    assert!(authorization.is_sensitive());
    connect_management_authorization_value("management-token")
        .expect_err("noncanonical management tokens must be rejected");
}
#[test]
fn vpn_tool_factories_expose_expected_names_and_routes() {
    let profile = iroha_vpn_profile_tool();
    assert_eq!(profile.name, "iroha.vpn.profile");
    assert_eq!(
        profile
            .route_backing()
            .expect("VPN profile tool must be route-backed")
            .2,
        "/v1/vpn/profile"
    );
    let quote = iroha_vpn_quotes_create_tool();
    assert_eq!(quote.name, "iroha.vpn.quotes.create");
    assert_eq!(
        quote
            .route_backing()
            .expect("VPN quote tool must be route-backed")
            .2,
        "/v1/vpn/quotes"
    );
    let quote_schema = quote.input_schema.as_object().expect("quote schema");
    let quote_properties = quote_schema
        .get("properties")
        .and_then(Value::as_object)
        .expect("quote properties");
    assert!(!quote_properties.contains_key("metering_public_key_hex"));
    assert!(!quote_properties.contains_key("headers"));
    assert!(quote_properties.contains_key("canonical_auth"));
    let quote_required = quote_schema
        .get("required")
        .and_then(Value::as_array)
        .expect("quote required fields");
    assert!(
        quote_required
            .iter()
            .any(|field| field.as_str() == Some("body"))
    );
    assert!(
        quote_required
            .iter()
            .any(|field| field.as_str() == Some("canonical_auth"))
    );
    let quote_body = quote_properties
        .get("body")
        .and_then(Value::as_object)
        .expect("quote body schema");
    assert_eq!(
        quote_body
            .get("additionalProperties")
            .and_then(Value::as_bool),
        Some(false)
    );
    assert!(
        quote_body
            .get("properties")
            .and_then(Value::as_object)
            .is_some_and(|properties| properties.contains_key("metering_public_key_hex"))
    );
    let quote_body_description = quote_properties
        .get("body")
        .and_then(Value::as_object)
        .and_then(|body| body.get("description"))
        .and_then(Value::as_str)
        .expect("quote body description");
    assert!(quote_body_description.contains("open_lease_instruction"));
    assert!(!quote_body_description.contains("tx_instructions"));
    let create = iroha_vpn_sessions_create_tool();
    assert_eq!(create.name, "iroha.vpn.sessions.create");
    assert_eq!(
        create
            .route_backing()
            .expect("VPN session-create tool must be route-backed")
            .2,
        "/v1/vpn/sessions"
    );
    let get = iroha_vpn_sessions_get_tool();
    assert_eq!(get.name, "iroha.vpn.sessions.get");
    assert_eq!(
        get.route_backing()
            .expect("VPN session-get tool must be route-backed")
            .2,
        "/v1/vpn/sessions/{session_id}"
    );
    let get_schema = get.input_schema.as_object().expect("session get schema");
    let get_properties = get_schema
        .get("properties")
        .and_then(Value::as_object)
        .expect("session get properties");
    assert!(get_properties.contains_key("session_id"));
    assert!(get_properties.contains_key("canonical_auth"));
    assert!(!get_properties.contains_key("id"));
    assert!(!get_properties.contains_key("path"));
    assert!(!get_properties.contains_key("headers"));
    assert_eq!(
        get_properties
            .get("session_id")
            .and_then(|schema| schema.get("pattern"))
            .and_then(Value::as_str),
        Some("^[0-9a-f]{32}$")
    );
    let receipts = iroha_vpn_receipts_list_tool();
    assert_eq!(receipts.name, "iroha.vpn.receipts.list");
    assert_eq!(
        receipts
            .route_backing()
            .expect("VPN receipt-list tool must be route-backed")
            .2,
        "/v1/vpn/receipts"
    );
    let receipt_submit = iroha_vpn_receipts_submit_tool();
    assert_eq!(receipt_submit.name, "iroha.vpn.receipts.submit");
    assert_eq!(
        receipt_submit
            .route_backing()
            .expect("VPN receipt-submit tool must be route-backed")
            .2,
        "/v1/vpn/receipts"
    );
    let schema = receipt_submit
        .input_schema
        .as_object()
        .expect("receipt submit schema");
    let properties = schema
        .get("properties")
        .and_then(Value::as_object)
        .expect("receipt submit properties");
    assert!(!properties.contains_key("lease_id_hex"));
    assert!(!properties.contains_key("headers"));
    assert!(properties.contains_key("canonical_auth"));
    assert!(
        properties
            .get("body")
            .and_then(|body| body.get("properties"))
            .and_then(Value::as_object)
            .is_some_and(|body| body.contains_key("lease_id_hex"))
    );
    let receipt_body_description = properties
        .get("body")
        .and_then(Value::as_object)
        .and_then(|body| body.get("description"))
        .and_then(Value::as_str)
        .expect("receipt body description");
    assert!(receipt_body_description.contains("settle_lease_instruction"));
    assert!(!receipt_body_description.contains("tx_instructions"));
    for tool in [quote, create, get, receipts, receipt_submit] {
        let descriptor = tool.descriptor();
        let schema = descriptor
            .get("inputSchema")
            .and_then(Value::as_object)
            .expect("published VPN input schema");
        assert!(!schema.contains_key(MCP_STRICT_BODY_SCHEMA_EXTENSION));
        let required = schema
            .get("required")
            .and_then(Value::as_array)
            .expect("published VPN required fields");
        assert!(
            required
                .iter()
                .any(|field| field.as_str() == Some("canonical_auth")),
            "{} must require an inner-target proof",
            tool.name
        );
        let canonical_auth = schema
            .get("properties")
            .and_then(|properties| properties.get("canonical_auth"))
            .expect("canonical_auth schema");
        assert_eq!(
            canonical_auth
                .get("additionalProperties")
                .and_then(Value::as_bool),
            Some(false)
        );
        assert_eq!(
            canonical_auth
                .get("oneOf")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(2)
        );
    }
}
#[test]
fn extract_vpn_session_id_argument_requires_exact_field() {
    let expected = "ab".repeat(16);
    let args = norito::json!({ "session_id": (expected.clone()) });
    let session_id = extract_vpn_session_id_argument(args.as_object().expect("object"))
        .expect("exact VPN session id");
    assert_eq!(session_id, expected);
}
#[test]
fn extract_vpn_session_id_argument_rejects_aliases() {
    for args in [
        norito::json!({ "id": "top-level-vpn-session" }),
        norito::json!({ "path": { "session_id": "nested-vpn-session" } }),
        norito::json!({ "session_id": ("AB".repeat(16)) }),
        norito::json!({ "session_id": ("ab".repeat(32)) }),
        norito::json!({ "session_id": "ab" }),
    ] {
        assert!(extract_vpn_session_id_argument(args.as_object().expect("object")).is_err());
    }
}
#[test]
fn append_query_arguments_accepts_flat_query_fields_when_query_absent() {
    let args = norito::json!({
        "account_id": TEST_ACCOUNT_I105,
        "limit": 20,
        "offset": 0,
        "headers": {"x": "1"}
    });
    let route = append_query_arguments(
        "/v1/test".to_owned(),
        args.as_object().expect("object"),
        &["account_id", "headers", "accept", "query"],
    )
    .expect("query route");
    assert_eq!(route, "/v1/test?limit=20&offset=0");
}
#[test]
fn append_query_arguments_rejects_non_object_query() {
    let args = norito::json!({
        "query": "not-an-object"
    });
    let err = append_query_arguments(
        "/v1/test".to_owned(),
        args.as_object().expect("object"),
        &["query"],
    )
    .expect_err("error");
    assert!(err.contains("`query` must be an object"));
}
#[test]
fn append_query_arguments_preserves_form_wire_and_rejects_composites() {
    let args = norito::json!({
        "star": "*",
        "tilde": "~",
        "space": "a b",
        "slash": "/"
    });
    let route = append_named_query_fields(
        "/v1/test".to_owned(),
        args.as_object().expect("object"),
        &["star", "tilde", "space", "slash"],
    )
    .expect("form route");
    assert_eq!(route, "/v1/test?star=*&tilde=%7E&space=a+b&slash=%2F");

    let composite = norito::json!({ "query": { "nested": { "value": 1 } } });
    append_query_arguments(
        "/v1/test".to_owned(),
        composite.as_object().expect("object"),
        &["query"],
    )
    .expect_err("composite query values must fail closed");
}
#[test]
fn query_projection_shard_catalog_fields_keep_legacy_lexical_order() {
    assert_eq!(
        QUERY_PROJECTION_SHARD_CATALOG_FIELDS,
        &["asset_definition_id", "limit", "offset"]
    );
}
#[test]
fn extract_account_id_argument_requires_canonical_path_field() {
    let args = norito::json!({
        "path": { "account_id": TEST_ACCOUNT_I105 }
    });
    let account_id =
        extract_account_id_argument(args.as_object().expect("object")).expect("account id");
    assert_eq!(account_id, TEST_ACCOUNT_I105);
}
#[test]
fn extract_uaid_argument_requires_canonical_path_field() {
    let args = norito::json!({
        "path": {
            "uaid": "uaid:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
        }
    });
    let uaid = extract_uaid_argument(args.as_object().expect("object")).expect("uaid");
    assert_eq!(
        uaid,
        "uaid:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    );
}
#[test]
fn extract_domain_id_argument_requires_canonical_path_field() {
    let args = norito::json!({
        "path": { "domain_id": "wonderland" }
    });
    let domain_id = extract_domain_id_argument(args.as_object().expect("object")).expect("domain");
    assert_eq!(domain_id, "wonderland");
}
#[test]
fn extract_subscription_id_argument_requires_canonical_path_field() {
    let args = norito::json!({
        "path": { "subscription_id": "sub-001" }
    });
    let subscription_id =
        extract_subscription_id_argument(args.as_object().expect("object")).expect("subscription");
    assert_eq!(subscription_id, "sub-001");
}
#[test]
fn canonical_entity_path_arguments_reject_retired_flat_aliases() {
    let cases: [(Value, fn(&Map) -> Result<String, String>); 6] = [
        (
            norito::json!({ "account_id": TEST_ACCOUNT_I105 }),
            extract_account_id_argument,
        ),
        (
            norito::json!({ "uaid": "uaid:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff" }),
            extract_uaid_argument,
        ),
        (
            norito::json!({ "domain_id": "wonderland" }),
            extract_domain_id_argument,
        ),
        (
            norito::json!({ "domain": "wonderland" }),
            extract_domain_id_argument,
        ),
        (
            norito::json!({ "subscription_id": "sub-001" }),
            extract_subscription_id_argument,
        ),
        (
            norito::json!({ "id": "sub-001" }),
            extract_subscription_id_argument,
        ),
    ];
    for (args, extract) in cases {
        extract(args.as_object().expect("object"))
            .expect_err("retired flat path alias must reject");
    }
}
#[test]
fn subscription_draft_arguments_reject_aliases_and_missing_body() {
    for args in [
        norito::json!({ "id": "sub-001", "body": { "authority": TEST_ACCOUNT_I105 } }),
        norito::json!({
            "path": { "subscription_id": "sub-001" },
            "body": { "authority": TEST_ACCOUNT_I105 }
        }),
    ] {
        assert!(extract_exact_subscription_id_argument(args.as_object().expect("object")).is_err());
    }
    let exact = norito::json!({
        "subscription_id": "sub-001",
        "body": { "authority": TEST_ACCOUNT_I105 }
    });
    let exact = exact.as_object().expect("object");
    assert_eq!(
        extract_exact_subscription_id_argument(exact).unwrap(),
        "sub-001"
    );
    assert!(
        build_required_exact_object_body(
            exact,
            &["authority"],
            &["authority"],
            "subscription action draft body",
        )
        .is_ok()
    );
    let missing_body = norito::json!({ "subscription_id": "sub-001" });
    assert!(
        build_required_exact_object_body(
            missing_body.as_object().expect("object"),
            &["authority"],
            &["authority"],
            "subscription action draft body",
        )
        .is_err()
    );
    let private_key = norito::json!({
        "subscription_id": "sub-001",
        "body": {
            "authority": TEST_ACCOUNT_I105,
            "private_key": "forbidden"
        }
    });
    assert!(
        build_required_exact_object_body(
            private_key.as_object().expect("object"),
            &["authority"],
            &["authority"],
            "subscription action draft body",
        )
        .is_err()
    );
}
#[test]
fn subscription_draft_tools_publish_exact_secret_free_inputs() {
    let create = iroha_subscriptions_create_tool();
    let create_schema = create.input_schema.as_object().expect("create schema");
    let create_required = create_schema
        .get("required")
        .and_then(Value::as_array)
        .expect("create required");
    assert_eq!(create_required, &[Value::String("body".to_owned())]);
    let create_body = create_schema
        .get("properties")
        .and_then(Value::as_object)
        .and_then(|properties| properties.get("body"))
        .and_then(Value::as_object)
        .expect("create body schema");
    assert_eq!(
        create_body.get("additionalProperties"),
        Some(&Value::Bool(false))
    );
    assert!(
        !create_body
            .get("properties")
            .and_then(Value::as_object)
            .expect("create body properties")
            .contains_key("private_key")
    );
    for tool in [
        iroha_subscriptions_pause_tool(),
        iroha_subscriptions_resume_tool(),
        iroha_subscriptions_cancel_tool(),
        iroha_subscriptions_keep_tool(),
        iroha_subscriptions_charge_now_tool(),
    ] {
        assert!(tool.description.contains("unsigned"));
        let schema = tool.input_schema.as_object().expect("action schema");
        let properties = schema
            .get("properties")
            .and_then(Value::as_object)
            .expect("action properties");
        assert!(properties.contains_key("subscription_id"));
        assert!(properties.contains_key("body"));
        assert!(!properties.contains_key("id"));
        assert!(!properties.contains_key("path"));
        let body_properties = properties
            .get("body")
            .and_then(Value::as_object)
            .and_then(|body| body.get("properties"))
            .and_then(Value::as_object)
            .expect("action body properties");
        assert!(body_properties.contains_key("authority"));
        assert!(!body_properties.contains_key("private_key"));
    }
}
#[test]
fn extract_iso20022_message_id_argument_requires_canonical_path_field() {
    let args = norito::json!({
        "path": { "msg_id": "msg-001" }
    });
    let msg_id = extract_iso20022_message_id_argument(args.as_object().expect("object"))
        .expect("message id");
    assert_eq!(msg_id, "msg-001");
}
#[test]
fn extract_ticket_argument_requires_canonical_path_field() {
    let args = norito::json!({
        "path": { "ticket": "manifest-ticket-001" }
    });
    let ticket = extract_ticket_argument(args.as_object().expect("object")).expect("ticket");
    assert_eq!(ticket, "manifest-ticket-001");
}
#[test]
fn governance_entity_arguments_require_exact_canonical_paths() {
    let proposal_id = "ab".repeat(32);
    let proposal_args = norito::json!({
        "path": { "id": (proposal_id.clone()) }
    });
    assert_eq!(
        extract_governance_proposal_id_argument(
            proposal_args.as_object().expect("proposal object")
        )
        .expect("proposal id"),
        proposal_id
    );
    let referendum_args = norito::json!({
        "path": { "id": "referendum-001" }
    });
    assert_eq!(
        extract_governance_selector_argument(
            referendum_args.as_object().expect("referendum object"),
            "id",
            "referendum id",
        )
        .expect("referendum id"),
        "referendum-001"
    );
    let tally_args = norito::json!({
        "path": { "id": "tally-001" }
    });
    assert_eq!(
        extract_governance_selector_argument(
            tally_args.as_object().expect("tally object"),
            "id",
            "tally id",
        )
        .expect("tally id"),
        "tally-001"
    );
    let lock_args = norito::json!({
        "path": { "rid": "referendum-002" }
    });
    assert_eq!(
        extract_governance_selector_argument(
            lock_args.as_object().expect("lock object"),
            "rid",
            "referendum id",
        )
        .expect("lock id"),
        "referendum-002"
    );
    for invalid in [
        norito::json!({ "proposal_id": (proposal_id.clone()) }),
        norito::json!({ "id": (proposal_id.clone()) }),
        norito::json!({ "path": { "proposal_id": (proposal_id.clone()) } }),
    ] {
        extract_governance_proposal_id_argument(invalid.as_object().expect("proposal aliases"))
            .expect_err("retired governance proposal alias must fail closed");
    }
    for invalid in [
        norito::json!({ "id": "referendum-003" }),
        norito::json!({ "referendum_id": "referendum-003" }),
        norito::json!({ "rid": "referendum-003" }),
        norito::json!({ "tally_id": "tally-003" }),
        norito::json!({ "path": { "referendum_id": "referendum-003" } }),
        norito::json!({ "path": { "tally_id": "tally-003" } }),
        norito::json!({
            "path": {},
            "referendum_id": "referendum-003"
        }),
        norito::json!({
            "path": { "id": "referendum-003" },
            "referendum_id": "referendum-003"
        }),
        norito::json!({
            "rid": "referendum-003",
            "unexpected": "ignored"
        }),
    ] {
        extract_governance_selector_argument(
            invalid.as_object().expect("invalid exact arguments"),
            "rid",
            "referendum id",
        )
        .expect_err("retired governance argument must fail closed");
    }
}
#[test]
fn canonical_message_and_ticket_paths_reject_retired_aliases() {
    let cases: [(Value, fn(&Map) -> Result<String, String>); 6] = [
        (
            norito::json!({ "msg_id": "msg-001" }),
            extract_iso20022_message_id_argument,
        ),
        (
            norito::json!({ "message_id": "msg-001" }),
            extract_iso20022_message_id_argument,
        ),
        (
            norito::json!({ "id": "msg-001" }),
            extract_iso20022_message_id_argument,
        ),
        (
            norito::json!({ "ticket": "manifest-ticket-001" }),
            extract_ticket_argument,
        ),
        (
            norito::json!({ "manifest_ticket": "manifest-ticket-001" }),
            extract_ticket_argument,
        ),
        (
            norito::json!({ "id": "manifest-ticket-001" }),
            extract_ticket_argument,
        ),
    ];
    for (args, extract) in cases {
        extract(args.as_object().expect("object"))
            .expect_err("retired identifier alias must reject");
    }
}
#[test]
fn governance_mcp_id_validators_match_first_release_grammars() {
    let maximum = "a".repeat(128);
    for selector in ["a", maximum.as_str(), "A9_selector~with.dots"] {
        require_governance_selector_v1("selector", selector).expect("canonical selector must pass");
    }
    let overlong = "a".repeat(129);
    for selector in [
        "",
        ".",
        ".hidden",
        "a/b",
        "a%2Fb",
        "a b",
        "a\0b",
        "投票",
        overlong.as_str(),
    ] {
        require_governance_selector_v1("selector", selector)
            .expect_err("noncanonical selector must fail");
    }
    require_governance_proposal_id_v1("proposal_id", &"ab".repeat(32))
        .expect("exact lowercase hash must pass");
    for proposal_id in [
        "ab".repeat(31),
        "AB".repeat(32),
        format!("0x{}", "ab".repeat(32)),
        format!("{}g", "ab".repeat(31)),
    ] {
        require_governance_proposal_id_v1("proposal_id", &proposal_id)
            .expect_err("noncanonical proposal id must fail");
    }
}
#[test]
fn governance_mcp_catalog_publishes_exact_id_grammars() {
    let cfg = iroha_config::parameters::actual::ToriiMcp::default();
    let tools = build_tool_specs(&cfg);
    let tool_schema = |name: &str| {
        let tool = tools
            .iter()
            .find(|tool| tool.name == name)
            .unwrap_or_else(|| panic!("missing governance MCP tool `{name}`"));
        sanitize_tool_input_schema(&tool.input_schema)
    };
    let assert_grammar = |schema: &Value, path: &[&str], pattern: &str, max_length: u64| {
        let field = schema_value_at(schema, path);
        assert_eq!(field.get("pattern").and_then(Value::as_str), Some(pattern));
        assert_eq!(
            field.get("maxLength").and_then(Value::as_u64),
            Some(max_length)
        );
    };
    let proposal = tool_schema("iroha.gov.proposals.get");
    assert_grammar(
        &proposal,
        &["properties", "path", "properties", "id"],
        GOVERNANCE_PROPOSAL_ID_V1_PATTERN,
        64,
    );
    for (tool, path_field) in [
        ("iroha.gov.locks.get", "rid"),
        ("iroha.gov.referenda.get", "id"),
        ("iroha.gov.tally.get", "id"),
    ] {
        let schema = tool_schema(tool);
        assert_grammar(
            &schema,
            &["properties", "path", "properties", path_field],
            iroha_data_model::governance::GOVERNANCE_SELECTOR_V1_PATTERN,
            iroha_data_model::governance::GOVERNANCE_SELECTOR_V1_MAX_BYTES as u64,
        );
    }
    for (tool, field, pattern, max_length) in [
        (
            "iroha.gov.ballots.zk_v1",
            "election_id",
            iroha_data_model::governance::GOVERNANCE_SELECTOR_V1_PATTERN,
            iroha_data_model::governance::GOVERNANCE_SELECTOR_V1_MAX_BYTES as u64,
        ),
        (
            "iroha.gov.ballots.zk_v1.ballot_proof",
            "election_id",
            iroha_data_model::governance::GOVERNANCE_SELECTOR_V1_PATTERN,
            iroha_data_model::governance::GOVERNANCE_SELECTOR_V1_MAX_BYTES as u64,
        ),
        (
            "iroha.gov.ballots.plain",
            "referendum_id",
            iroha_data_model::governance::GOVERNANCE_SELECTOR_V1_PATTERN,
            iroha_data_model::governance::GOVERNANCE_SELECTOR_V1_MAX_BYTES as u64,
        ),
    ] {
        let schema = tool_schema(tool);
        assert!(
            schema_value_at(&schema, &["properties"])
                .as_object()
                .is_some_and(|properties| !properties.contains_key(field)),
            "{tool} must publish `{field}` only inside `body`"
        );
        assert_grammar(
            &schema,
            &["properties", "body", "properties", field],
            pattern,
            max_length,
        );
    }
}
#[test]
fn parliament_mcp_catalog_exposes_authenticated_draft_and_read_tools() {
    let cfg = iroha_config::parameters::actual::ToriiMcp::default();
    let tools = build_tool_specs(&cfg);
    for (name, method, path, effect) in [
        (
            "iroha.gov.parliament.attempts.draft",
            Method::POST,
            "/v1/gov/parliament/attempts/draft",
            ToolEffect::BuildInstruction,
        ),
        (
            "iroha.gov.parliament.attempts.get",
            Method::GET,
            "/v1/gov/parliament/attempts/{governance_attempt_id}",
            ToolEffect::Read,
        ),
        (
            "iroha.gov.parliament.transitions.draft",
            Method::POST,
            "/v1/gov/parliament/transitions/draft",
            ToolEffect::BuildInstruction,
        ),
    ] {
        let tool = tools
            .iter()
            .find(|tool| tool.name == name)
            .unwrap_or_else(|| panic!("missing Parliament MCP tool `{name}`"));
        let (actual_effect, actual_method, actual_path) = tool
            .route_backing()
            .expect("Parliament MCP tool must be route-backed");
        assert_eq!(actual_method, &method);
        assert_eq!(actual_path, path);
        assert_eq!(actual_effect, effect);
        let schema = sanitize_tool_input_schema(&tool.input_schema);
        assert_eq!(
            schema.get("additionalProperties").and_then(Value::as_bool),
            Some(false)
        );
        let required = schema
            .get("required")
            .and_then(Value::as_array)
            .expect("authenticated Parliament tool required fields");
        assert!(
            required
                .iter()
                .any(|field| field.as_str() == Some("headers"))
        );
    }
}
#[test]
fn parliament_mcp_dispatch_requires_exact_nonzero_attempt_id() {
    let expected = format!("01{}", "ab".repeat(31));
    let arguments = norito::json!({
        "path": { "governance_attempt_id": (expected.clone()) }
    });
    assert_eq!(
        extract_parliament_attempt_id_argument(arguments.as_object().expect("arguments object"))
            .expect("canonical Parliament attempt id"),
        expected
    );

    for rejected in [
        norito::json!({ "governance_attempt_id": ("ab".repeat(32)) }),
        norito::json!({ "path": { "id": ("ab".repeat(32)) } }),
        norito::json!({ "path": { "governance_attempt_id": ("AB".repeat(32)) } }),
        norito::json!({ "path": { "governance_attempt_id": ("00".repeat(32)) } }),
        norito::json!({
            "path": {
                "governance_attempt_id": ("ab".repeat(32)),
                "unexpected": true
            }
        }),
    ] {
        assert!(
            extract_parliament_attempt_id_argument(rejected.as_object().expect("arguments object"))
                .is_err()
        );
    }
}
#[test]
fn parliament_mcp_dispatch_requires_explicit_json_body() {
    let expected_body = norito::json!({
        "version": 1,
        "governance_attempt_id": ("ab".repeat(32)),
        "transition": { "BeginCitizenSnapshot": { "snapshot_height": 7 } }
    });
    let arguments = norito::json!({ "body": (expected_body.clone()) });
    let encoded = parliament_json_body(
        arguments.as_object().expect("arguments object"),
        "Parliament transition draft",
    )
    .expect("explicit Parliament JSON body");
    let decoded: Value = norito::json::from_slice(&encoded).expect("decode Parliament JSON body");
    assert_eq!(decoded, expected_body);

    for rejected in [
        norito::json!({ "version": 1 }),
        norito::json!({ "body": "not-an-object" }),
        norito::json!({ "body": {}, "query": {} }),
    ] {
        assert!(
            parliament_json_body(
                rejected.as_object().expect("arguments object"),
                "Parliament transition draft",
            )
            .is_err()
        );
    }
}
#[test]
fn governance_mcp_catalog_preserves_required_body_or_flat_forms() {
    let cfg = iroha_config::parameters::actual::ToriiMcp::default();
    let tools = build_tool_specs(&cfg);
    let tool_schema = |name: &str| {
        let tool = tools
            .iter()
            .find(|tool| tool.name == name)
            .unwrap_or_else(|| panic!("missing governance MCP tool `{name}`"));
        sanitize_tool_input_schema(&tool.input_schema)
    };
    let assert_required = |schema: &Value, path: &[&str], fields: &[&str]| {
        let expected = fields
            .iter()
            .map(|field| Value::String((*field).to_owned()))
            .collect::<Vec<_>>();
        let actual = schema_value_at(schema, path)
            .as_array()
            .unwrap_or_else(|| panic!("required fields at {path:?} are not an array"));
        assert_eq!(
            actual.as_slice(),
            expected.as_slice(),
            "required fields at {path:?}"
        );
    };
    for (name, path_field) in [
        ("iroha.gov.proposals.get", "id"),
        ("iroha.gov.locks.get", "rid"),
        ("iroha.gov.referenda.get", "id"),
        ("iroha.gov.tally.get", "id"),
    ] {
        let schema = tool_schema(name);
        assert_required(&schema, &["required"], &["path", "headers"]);
        assert_required(&schema, &["properties", "path", "required"], &[path_field]);
    }
    for (name, fields) in [
        (
            "iroha.gov.ballots.zk_v1",
            &[
                "network_id",
                "authority",
                "election_id",
                "backend",
                "envelope_b64",
            ][..],
        ),
        (
            "iroha.gov.ballots.zk_v1.ballot_proof",
            &["network_id", "authority", "election_id", "ballot"][..],
        ),
        (
            "iroha.gov.ballots.plain",
            &[
                "network_id",
                "authority",
                "referendum_id",
                "owner",
                "amount",
                "duration_blocks",
                "direction",
            ][..],
        ),
    ] {
        let schema = tool_schema(name);
        assert_required(&schema, &["properties", "body", "required"], fields);
        if name.starts_with("iroha.gov.ballots.") {
            assert_required(&schema, &["required"], &["body", "headers"]);
            let headers = schema_value_at(&schema, &["properties", "headers"])
                .as_object()
                .expect("governance canonical headers schema");
            assert_eq!(
                headers.get("additionalProperties").and_then(Value::as_bool),
                Some(false)
            );
            assert_eq!(
                headers.get("oneOf").and_then(Value::as_array).map(Vec::len),
                Some(2),
                "governance auth schema must expose signature and witness branches"
            );
            let header_properties = headers
                .get("properties")
                .and_then(Value::as_object)
                .expect("governance header properties");
            for header in [
                "X-Iroha-Account",
                "X-Iroha-Signature",
                "X-Iroha-Timestamp-Ms",
                "X-Iroha-Nonce",
                "X-Iroha-Witness",
            ] {
                let property = header_properties
                    .get(header)
                    .and_then(Value::as_object)
                    .unwrap_or_else(|| panic!("missing strict governance header `{header}`"));
                assert!(property.get("maxLength").is_some());
                assert!(property.get("pattern").is_some());
            }
            let authority =
                schema_value_at(&schema, &["properties", "body", "properties", "authority"])
                    .as_object()
                    .expect("governance authority schema");
            let description = authority
                .get("description")
                .and_then(Value::as_str)
                .expect("governance authority description");
            assert!(description.contains("JSON ballot body"));
            assert!(!description.contains("equal to X-Iroha-Account"));
        }
    }
    let proof = tool_schema("iroha.gov.ballots.zk_v1.ballot_proof");
    assert_required(
        &proof,
        &["properties", "body", "properties", "ballot", "required"],
        &["backend", "envelope_bytes"],
    );
}
#[test]
fn openapi_governance_mcp_catalog_requires_inspectable_json_bodies() {
    let cfg = iroha_config::parameters::actual::ToriiMcp::default();
    let tools = build_tool_specs(&cfg);
    {
        let target_path = "/v1/zk/vote/tally";
        let tool = tools
            .iter()
            .find(|tool| {
                tool.name.starts_with("torii.")
                    && tool
                        .route_backing()
                        .is_some_and(|(_, method, path_template)| {
                            method == Method::POST && path_template == target_path
                        })
            })
            .unwrap_or_else(|| panic!("missing OpenAPI-derived governance tool for {target_path}"));
        let schema = sanitize_tool_input_schema(&tool.input_schema);
        let required = schema
            .get("required")
            .and_then(Value::as_array)
            .expect("OpenAPI-derived governance required fields");
        assert!(
            required.iter().any(|field| field.as_str() == Some("body")),
            "{target_path} must require the inspected JSON body"
        );
        let properties = schema
            .get("properties")
            .and_then(Value::as_object)
            .expect("OpenAPI-derived governance properties");
        assert!(
            !properties.contains_key("body_base64"),
            "{target_path} must not advertise an opaque body bypass"
        );
        assert_eq!(
            properties
                .get("content_type")
                .and_then(|schema| schema.get("const"))
                .and_then(Value::as_str),
            Some("application/json")
        );
        let body = properties
            .get("body")
            .expect("typed governance body schema");
        let body_is_closed = body.get("additionalProperties").and_then(Value::as_bool)
            == Some(false)
            || body
                .get("oneOf")
                .and_then(Value::as_array)
                .is_some_and(|branches| {
                    !branches.is_empty()
                        && branches.iter().all(|branch| {
                            branch.get("additionalProperties").and_then(Value::as_bool)
                                == Some(false)
                        })
                });
        assert!(
            body_is_closed,
            "{target_path} must preserve its closed typed body schema"
        );
    }
    for target_path in [
        "/v1/gov/ballots/zk-v1",
        "/v1/gov/ballots/zk-v1/ballot-proof",
        "/v1/gov/ballots/plain",
    ] {
        assert!(
            tools.iter().all(|tool| {
                !(tool.name.starts_with("torii.")
                    && tool
                        .route_backing()
                        .is_some_and(|(_, method, path_template)| {
                            method == Method::POST && path_template == target_path
                        }))
            }),
            "purpose-built governance tool must not have a generated alias for {target_path}"
        );
    }
    for retired_path in [
        "/v1/gov/parliament/ballots",
        "/v1/gov/finalize",
        "/v1/gov/enact",
    ] {
        assert!(
            tools.iter().all(|tool| match tool.route_backing() {
                Some((_, _, path_template)) => path_template != retired_path,
                None => true,
            }),
            "retired proposal-backed governance route remains exposed through MCP: {retired_path}"
        );
    }
    for retired_tool in ["iroha.gov.finalize", "iroha.gov.enact"] {
        assert!(
            tools.iter().all(|tool| tool.name != retired_tool),
            "retired proposal-backed governance MCP tool remains registered: {retired_tool}"
        );
    }
}
/// Every collection tool with its query shape and single path parameter.
const COLLECTION_TOOL_SHAPES: [(&str, CollectionQueryShape, Option<&str>); 40] = [
    ("iroha.accounts.list", CollectionQueryShape::Get, None),
    ("iroha.accounts.query", CollectionQueryShape::Post, None),
    ("iroha.domains.list", CollectionQueryShape::Get, None),
    ("iroha.domains.query", CollectionQueryShape::Post, None),
    ("iroha.assets.definitions", CollectionQueryShape::Get, None),
    (
        "iroha.assets.definitions.query",
        CollectionQueryShape::Post,
        None,
    ),
    ("iroha.nfts.chain.list", CollectionQueryShape::Get, None),
    ("iroha.nfts.query", CollectionQueryShape::Post, None),
    ("iroha.rwas.chain.list", CollectionQueryShape::Get, None),
    ("iroha.rwas.query", CollectionQueryShape::Post, None),
    (
        "iroha.accounts.assets",
        CollectionQueryShape::Get,
        Some("account_id"),
    ),
    (
        "iroha.accounts.assets.query",
        CollectionQueryShape::Post,
        Some("account_id"),
    ),
    (
        "iroha.assets.holders",
        CollectionQueryShape::Get,
        Some("definition_id"),
    ),
    (
        "iroha.assets.holders.query",
        CollectionQueryShape::Post,
        Some("definition_id"),
    ),
    (
        "iroha.accounts.transactions",
        CollectionQueryShape::HistoryGet,
        Some("account_id"),
    ),
    (
        "iroha.accounts.transactions.query",
        CollectionQueryShape::HistoryPost,
        Some("account_id"),
    ),
    (
        "iroha.transactions.query",
        CollectionQueryShape::HistoryPost,
        None,
    ),
    (
        "iroha.accounts.permissions",
        CollectionQueryShape::Get,
        Some("account_id"),
    ),
    (
        "iroha.accounts.permissions.query",
        CollectionQueryShape::Post,
        Some("account_id"),
    ),
    (
        "iroha.subscriptions.plans.list",
        CollectionQueryShape::Get,
        None,
    ),
    (
        "iroha.subscriptions.plans.query",
        CollectionQueryShape::Post,
        None,
    ),
    ("iroha.subscriptions.list", CollectionQueryShape::Get, None),
    (
        "iroha.subscriptions.query",
        CollectionQueryShape::Post,
        None,
    ),
    (
        "iroha.space_directory.manifests",
        CollectionQueryShape::Get,
        Some("uaid"),
    ),
    (
        "iroha.space_directory.manifests.query",
        CollectionQueryShape::Post,
        Some("uaid"),
    ),
    (
        "iroha.accounts.history",
        CollectionQueryShape::HistoryGet,
        Some("account_id"),
    ),
    (
        "iroha.accounts.history.query",
        CollectionQueryShape::HistoryPost,
        Some("account_id"),
    ),
    (
        "iroha.contracts.activity.query",
        CollectionQueryShape::HistoryPost,
        None,
    ),
    (
        "iroha.contracts.events.query",
        CollectionQueryShape::HistoryPost,
        None,
    ),
    (
        "iroha.explorer.accounts.query",
        CollectionQueryShape::HistoryPost,
        None,
    ),
    (
        "iroha.explorer.domains.query",
        CollectionQueryShape::HistoryPost,
        None,
    ),
    (
        "iroha.explorer.asset_definitions.query",
        CollectionQueryShape::HistoryPost,
        None,
    ),
    (
        "iroha.explorer.assets.query",
        CollectionQueryShape::HistoryPost,
        None,
    ),
    (
        "iroha.explorer.nfts.query",
        CollectionQueryShape::HistoryPost,
        None,
    ),
    (
        "iroha.explorer.rwas.query",
        CollectionQueryShape::HistoryPost,
        None,
    ),
    (
        "iroha.explorer.blocks.query",
        CollectionQueryShape::HistoryPost,
        None,
    ),
    (
        "iroha.explorer.transactions.query",
        CollectionQueryShape::HistoryPost,
        None,
    ),
    (
        "iroha.explorer.transactions.latest.query",
        CollectionQueryShape::HistoryPost,
        None,
    ),
    (
        "iroha.explorer.instructions.query",
        CollectionQueryShape::HistoryPost,
        None,
    ),
    (
        "iroha.explorer.instructions.latest.query",
        CollectionQueryShape::HistoryPost,
        None,
    ),
];
#[test]
fn collection_tools_advertise_the_shared_collection_query_controls() {
    let cfg = iroha_config::parameters::actual::ToriiMcp {
        profile: ToriiMcpProfile::Operator,
        expose_operator_routes: true,
        ..Default::default()
    };
    let tools = build_tool_specs(&cfg);
    for (name, shape, path_key) in COLLECTION_TOOL_SHAPES {
        let tool = tools
            .iter()
            .find(|tool| tool.name == name)
            .unwrap_or_else(|| panic!("collection tool `{name}` is registered"));
        let schema = tool.input_schema.as_object().expect("object input schema");
        assert!(
            !schema.contains_key(collection_query_tools::COLLECTION_QUERY_SCHEMA_EXTENSION),
            "{name} must expand its collection marker"
        );
        assert_eq!(
            schema.get("additionalProperties"),
            Some(&Value::Bool(false)),
            "{name} must reject unknown arguments"
        );
        let properties = schema
            .get("properties")
            .and_then(Value::as_object)
            .expect("input properties");
        let controls = collection_query_tools::collection_query_properties(shape);
        let mut expected = controls.keys().map(String::as_str).collect::<BTreeSet<_>>();
        expected.extend(["headers", "accept"]);
        if let Some(path_key) = path_key {
            expected.insert("path");
            assert!(
                schema_requires(schema, "path"),
                "{name} must require its route path"
            );
            assert!(
                properties["path"]["properties"].get(path_key).is_some(),
                "{name} path must name `{path_key}`"
            );
        }
        assert_eq!(
            properties
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            expected,
            "{name} must advertise exactly the shared controls of {shape:?}"
        );
        for (control, property) in &controls {
            assert_eq!(&properties[control], property, "{name} `{control}`");
        }
        let (effect, method, path) = tool.route_backing().expect("route-backed collection tool");
        assert_eq!(effect, ToolEffect::Read, "{name}");
        let route = route_catalog::CATALOGED_ROUTES
            .iter()
            .find(|route| route.path() == path && Some(route.method()) == catalog_method(method))
            .unwrap_or_else(|| panic!("collection tool `{name}` has a catalog descriptor"));
        assert_eq!(
            route.effect(),
            RouteEffect::ReadOnly,
            "{name} catalog effect"
        );
        let expected_method = match shape {
            CollectionQueryShape::Get | CollectionQueryShape::HistoryGet => Method::GET,
            CollectionQueryShape::Post | CollectionQueryShape::HistoryPost => Method::POST,
        };
        assert_eq!(method, &expected_method, "{name}");
        for needle in ["next_cursor", "cursor", "null"] {
            assert!(
                tool.description.contains(needle),
                "{name} description must include {needle:?}"
            );
        }
        // Bounded Explorer world feeds share the history control shape but use
        // canonical entity order. The shape promises fixed order, not chronology.
        let fixed_order = matches!(
            shape,
            CollectionQueryShape::HistoryGet | CollectionQueryShape::HistoryPost
        );
        if fixed_order {
            assert!(
                tool.description.contains("newest")
                    || tool.description.contains("Fixed bounded order"),
                "{name} must state its fixed order"
            );
        }

        let mut arguments = Map::new();
        if let Some(path_key) = path_key {
            let mut path = Map::new();
            path.insert(path_key.to_owned(), Value::from("x"));
            arguments.insert("path".to_owned(), Value::Object(path));
        }
        arguments.insert("filter".to_owned(), Value::from("block_height >= 1"));
        arguments.insert("select".to_owned(), Value::from("id"));
        arguments.insert("limit".to_owned(), Value::from(5_u64));
        arguments.insert("cursor".to_owned(), Value::from("c1_A-z"));
        validate_tool_arguments(tool, &arguments)
            .unwrap_or_else(|error| panic!("{name} rejected canonical arguments: {error}"));
        if fixed_order {
            for (control, value) in [
                ("sort", norito::json!(["-id"])),
                ("include_total", Value::Bool(true)),
                (
                    "aggregate",
                    norito::json!({"metrics": [{"alias": "n", "fn": "count"}]}),
                ),
            ] {
                let mut unsupported = arguments.clone();
                unsupported.insert(control.to_owned(), value);
                assert!(
                    validate_tool_arguments(tool, &unsupported).is_err(),
                    "{name} must reject unsupported `{control}`"
                );
            }
        }
        for retired in ["offset", "pagination", "fetch_size", "count_mode", "query"] {
            let mut retired_arguments = arguments.clone();
            retired_arguments.insert(retired.to_owned(), Value::from(1_u64));
            assert!(
                validate_tool_arguments(tool, &retired_arguments).is_err(),
                "{name} must reject retired `{retired}`"
            );
        }
        let mut zero_limit = arguments.clone();
        zero_limit.insert("limit".to_owned(), Value::from(0_u64));
        assert!(
            validate_tool_arguments(tool, &zero_limit).is_err(),
            "{name} must reject `limit: 0`"
        );
    }
    // The table above is the complete collection inventory: no other tool
    // carries the shared query controls.
    let collection_names = COLLECTION_TOOL_SHAPES
        .iter()
        .map(|(name, _, _)| *name)
        .collect::<BTreeSet<_>>();
    let shared_controls =
        collection_query_tools::collection_query_properties(CollectionQueryShape::Get);
    let shared_filter = &shared_controls["filter"];
    for tool in &tools {
        if collection_names.contains(tool.name.as_str()) || !tool.name.starts_with("iroha.") {
            continue;
        }
        let properties = tool
            .input_schema
            .get("properties")
            .and_then(Value::as_object);
        assert!(
            properties.is_none_or(|properties| {
                properties.get("filter") != Some(shared_filter)
                    && !properties.contains_key("include_total")
            }),
            "{} is not in the collection tool inventory but advertises its query controls",
            tool.name
        );
    }
}
/// Router capturing each dispatched request's method, path with query and body.
fn install_collection_request_capturing_router(
    app: &mut SharedAppState,
    requests: std::sync::Arc<std::sync::Mutex<Vec<(Method, String, Vec<u8>)>>>,
) -> McpDispatchRouterOwner {
    let router: axum::Router =
        axum::Router::new().fallback_service(tower::service_fn(move |request: Request<Body>| {
            let requests = std::sync::Arc::clone(&requests);
            async move {
                let (parts, body) = request.into_parts();
                let body = axum::body::to_bytes(body, 64 * 1024)
                    .await
                    .expect("nested collection request body");
                requests
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push((
                        parts.method,
                        parts
                            .uri
                            .path_and_query()
                            .map_or_else(String::new, ToString::to_string),
                        body.to_vec(),
                    ));
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(r#"{"items":[],"next_cursor":null}"#))
                        .expect("response"),
                )
            }
        }));
    app.mcp_dispatch_router.install(router)
}
#[tokio::test]
async fn collection_tools_send_the_parsed_query_to_their_routes() {
    use iroha_torii_shared::list_query::ListQuery;

    let mut app = mk_app_state_for_tests();
    let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let _router_owner =
        install_collection_request_capturing_router(&mut app, std::sync::Arc::clone(&requests));
    let headers = HeaderMap::new();
    let arguments = |value: Value| match value {
        Value::Object(map) => map,
        other => panic!("tool arguments must be an object, got {other:?}"),
    };

    let accounts = arguments(norito::json!({
        "filter": { "op": "gte", "args": ["metadata.tier", 2] },
        "sort": ["-id"],
        "select": "id,label",
        "limit": 2
    }));
    let page = dispatch_iroha_accounts_list(&app, &headers, &accounts)
        .await
        .expect("GET collection dispatch");
    assert_eq!(page["status"].as_u64(), Some(200));
    let holders = arguments(norito::json!({
        "path": { "definition_id": "62Fk4FPcMuLvW5QjDGNF2a4jAmjM" },
        "filter": "quantity > 0",
        "sort": "-quantity",
        "limit": 3
    }));
    dispatch_iroha_asset_holders(&app, &headers, &holders)
        .await
        .expect("path GET collection dispatch");
    let assets = arguments(norito::json!({
        "path": { "account_id": TEST_ACCOUNT_I105 },
        "filter": "quantity >= 10.5",
        "aggregate": {
            "group_by": ["asset"],
            "metrics": [{ "alias": "supply", "fn": "sum", "field": "quantity" }]
        },
        "sort": "-supply",
        "limit": 4
    }));
    dispatch_iroha_account_assets_query(&app, &headers, &assets)
        .await
        .expect("path POST collection dispatch");
    let transactions = arguments(norito::json!({
        "body": { "filter": "block_height >= 1200", "select": ["entrypoint_hash"], "limit": 5 }
    }));
    dispatch_iroha_transactions_query(&app, &headers, &transactions)
        .await
        .expect("POST history dispatch");
    for (rejected, needle) in [
        (
            norito::json!({ "limit": 2, "offset": 0 }),
            "`offset` is retired",
        ),
        (
            norito::json!({ "body": { "limit": 2 }, "cursor": "c1" }),
            "`body` already holds the complete query",
        ),
        (norito::json!({ "filter": "id = = 1" }), "invalid `filter`"),
    ] {
        let error = dispatch_iroha_domains_query(&app, &headers, &arguments(rejected))
            .await
            .expect_err("invalid collection arguments fail before dispatch");
        assert!(error.contains(needle), "{error}");
    }
    let aggregate_get = arguments(norito::json!({
        "aggregate": { "metrics": [{ "alias": "n", "fn": "count" }] }
    }));
    let error = dispatch_iroha_domains_list(&app, &headers, &aggregate_get)
        .await
        .expect_err("aggregates have no GET form");
    assert!(error.contains("POST /query"), "{error}");

    let requests = requests
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert_eq!(requests.len(), 4, "only valid queries reach Torii routes");
    assert_eq!(requests[0].0, Method::GET);
    assert_eq!(
        requests[0].1,
        "/v1/accounts?filter=metadata.tier+%3E%3D+2&sort=-id&select=id%2Clabel&limit=2"
    );
    assert!(requests[0].2.is_empty());
    assert_eq!(requests[1].0, Method::GET);
    assert_eq!(
        requests[1].1,
        "/v1/assets/62Fk4FPcMuLvW5QjDGNF2a4jAmjM/holders?filter=quantity+%3E+0&sort=-quantity&limit=3"
    );
    assert_eq!(requests[2].0, Method::POST);
    assert!(
        requests[2].1.starts_with("/v1/accounts/") && requests[2].1.ends_with("/assets/query"),
        "{}",
        requests[2].1
    );
    let assets_body = json::from_slice::<Value>(&requests[2].2).expect("JSON collection body");
    assert_eq!(assets_body["sort"], norito::json!(["-supply"]));
    assert_eq!(
        ListQuery::from_json_value(assets_body).expect("canonical collection body"),
        collection_query_tools::list_query_from_tool_arguments(&assets)
            .expect("assets collection query")
    );
    assert_eq!(
        (requests[3].0.clone(), requests[3].1.as_str()),
        (Method::POST, "/v1/transactions/query")
    );
    let transactions_body = json::from_slice::<Value>(&requests[3].2).expect("JSON history body");
    assert_eq!(
        transactions_body,
        norito::json!({
            "filter": (iroha_torii_shared::list_query::FilterExpr::parse("block_height >= 1200")
                .expect("filter")
                .to_json_value()),
            "select": ["entrypoint_hash"],
            "limit": 5
        })
    );
}
#[path = "dispatch_and_argument_tests/canonical_paths_and_status.rs"]
mod canonical_paths_and_status;
