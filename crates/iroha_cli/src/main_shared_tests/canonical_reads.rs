//! Canonical CLI read requests, authority selection, and response projections.

use super::*;

#[derive(Debug)]
struct CanonicalReadTransport {
    requests: std::sync::Mutex<Vec<iroha::http::TransportRequest>>,
    responses: std::sync::Mutex<std::collections::VecDeque<iroha::http::Response<Vec<u8>>>>,
}
impl iroha::http::HttpTransport for CanonicalReadTransport {
    fn send_blocking(
        &self,
        request: iroha::http::TransportRequest,
    ) -> Result<iroha::http::Response<Vec<u8>>> {
        self.requests.lock().unwrap().push(request);
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .ok_or_else(|| eyre!("unexpected extra canonical read request"))
    }
    fn send(&self, request: iroha::http::TransportRequest) -> iroha::http::TransportFuture<'_> {
        Box::pin(async move { self.send_blocking(request) })
    }
}
struct CanonicalReadContext {
    config: Config,
    client: Client,
    i18n: Localizer,
    output: Option<String>,
    operator_key_pair: Option<KeyPair>,
    submitted: Option<Vec<InstructionBox>>,
}
impl RunContext for CanonicalReadContext {
    fn config(&self) -> &Config {
        &self.config
    }
    fn transaction_metadata(&self) -> Option<&Metadata> {
        None
    }
    fn input_instructions(&self) -> bool {
        false
    }
    fn output_instructions(&self) -> bool {
        false
    }
    fn i18n(&self) -> &Localizer {
        &self.i18n
    }
    fn print_data<T: JsonSerialize + ?Sized>(&mut self, data: &T) -> Result<()> {
        self.output = Some(norito::json::to_json(data)?);
        Ok(())
    }
    fn println(&mut self, data: impl std::fmt::Display) -> Result<()> {
        self.output = Some(data.to_string());
        Ok(())
    }
    fn client_from_config(&self) -> Result<Client> {
        Ok(self.client.clone())
    }
    fn operator_key_pair(&self) -> Option<&KeyPair> {
        self.operator_key_pair.as_ref()
    }
    fn submit_with_metadata(
        &mut self,
        instructions: impl Into<Executable>,
        _metadata: Metadata,
        wait_for_confirmation: bool,
    ) -> Result<()> {
        assert!(
            wait_for_confirmation,
            "committee submission waits for finality"
        );
        let Executable::Instructions(instructions) = instructions.into() else {
            eyre::bail!("expected exact preparation instructions")
        };
        self.submitted = Some(instructions.into_vec());
        Ok(())
    }
}
fn canonical_read_context(
    responses: Vec<iroha::http::Response<Vec<u8>>>,
) -> (CanonicalReadContext, std::sync::Arc<CanonicalReadTransport>) {
    let config = fallback_config();
    let transport = std::sync::Arc::new(CanonicalReadTransport {
        requests: std::sync::Mutex::new(Vec::new()),
        responses: std::sync::Mutex::new(responses.into()),
    });
    let client = Client::builder(config.clone())
        .http_transport(transport.clone())
        .build()
        .expect("canonical read client");
    (
        CanonicalReadContext {
            config,
            client,
            i18n: Localizer::new(Bundle::Cli, Language::English),
            output: None,
            operator_key_pair: None,
            submitted: None,
        },
        transport,
    )
}
#[test]
fn transaction_get_uses_exact_authenticated_details_and_preserves_rejection() {
    use iroha::data_model::{
        query::{
            CommittedTransaction, CommittedTxFilters, QueryRequest, SignedQuery,
            dsl::CompoundPredicate,
        },
        transaction::{TransactionResult, error::TransactionRejectionReason},
    };
    use iroha_version::codec::DecodeVersioned;
    use norito::codec::Decode;

    let config = fallback_config();
    let signed = TransactionBuilder::new(
        config.network_id,
        config.account.clone(),
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .try_sign(config.key_pair.private_key())
    .expect("sign exact transaction fixture");
    let hash = signed.hash_as_entrypoint();
    let result = TransactionResult::new(Err(TransactionRejectionReason::Validation(
        ValidationFail::NotPermitted("fixture contract permission denied".to_owned()),
    )));
    let output = iroha::data_model::block::execution_output::ExecutionOutputV1::Network(
        iroha::data_model::block::execution_output::NetworkExecutionOutputV1 {
            input_index: 0,
            result,
            completions: Vec::new(),
        },
    );
    let transaction = CommittedTransaction {
        block_hash: HashOf::from_untyped_unchecked(Hash::new(b"exact CLI transaction block")),
        entrypoint_hash: hash,
        entrypoint_proof: iroha_crypto::MerkleProof::from_audit_path(0, Vec::new()),
        entrypoint: TransactionEntrypoint::External(signed),
        output_hash: iroha_crypto::HashOf::new(&output),
        output_proof: iroha_crypto::MerkleProof::from_audit_path(0, Vec::new()),
        output,
    };
    for mismatched_hash in [false, true] {
        let details = iroha_torii_shared::PipelineTransactionDetailsResponse {
            hash: if mismatched_hash {
                HashOf::<TransactionEntrypoint>::from_untyped_unchecked(Hash::new(
                    b"other entrypoint",
                ))
                .to_string()
            } else {
                hash.to_string()
            },
            transaction: transaction.clone(),
        };
        let capabilities = iroha::http::Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(
                format!(
                    "{{\"data_model_version\":{}}}",
                    iroha::data_model::DATA_MODEL_VERSION
                )
                .into_bytes(),
            )
            .unwrap();
        let response = iroha::http::Response::builder()
            .status(200)
            .header("content-type", "application/x-norito")
            .body(norito::to_bytes(&details).unwrap())
            .unwrap();
        let (mut context, transport) = canonical_read_context(vec![capabilities, response]);
        let hash_literal = hash.to_string();
        let outcome = Args::try_parse_from(["iroha", "tx", "get", "--hash", &hash_literal])
            .unwrap()
            .command
            .run(&mut context);
        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests.len(), 2, "one capability read and one exact query");
        assert_eq!(requests[1].method, iroha::http::Method::POST);
        assert_eq!(requests[1].url.path(), "/v1/pipeline/transactions/details");
        let query = SignedQuery::decode_all_versioned(&requests[1].body).unwrap();
        query.verify_signature().unwrap();
        assert_eq!(query.authority(), &config.account);
        let QueryRequest::Start(query) = query.request() else {
            panic!("transaction get must sign an exact transaction-details query");
        };
        let (_, predicate, _, _) = query.parts();
        let predicate =
            CompoundPredicate::<CommittedTransaction>::decode(&mut std::io::Cursor::new(predicate))
                .unwrap();
        assert_eq!(
            predicate.committed_tx_filters(),
            Some(CommittedTxFilters {
                entry_eq: Some(hash),
                ..CommittedTxFilters::default()
            })
        );
        if mismatched_hash {
            assert!(outcome.is_err(), "a substituted proof must fail");
            assert!(context.output.is_none());
        } else {
            outcome.expect("rejected transactions still have readable details");
            assert_eq!(
                context.output,
                Some(norito::json::to_json(&transaction).unwrap())
            );
        }
    }
}
fn effective_permission_page(
    names: &[&str],
    cursor: Option<&str>,
) -> iroha::http::Response<Vec<u8>> {
    let items: Vec<_> = names
        .iter()
        .map(|name| {
            Permission::new(
                (*name).to_owned(),
                iroha_primitives::json::Json::from(norito::json!({})),
            )
        })
        .collect();
    let page = iroha::collections::Page {
        items,
        next_cursor: cursor.map(str::to_owned),
        total: None,
    };
    iroha::http::Response::builder()
        .status(200)
        .header("content-type", "application/json; charset=utf-8")
        .header("x-iroha-account-permission-semantics", "effective-v1")
        .body(norito::json::to_vec(&page).unwrap())
        .unwrap()
}
#[test]
fn account_permission_list_uses_shared_cursor_pages() {
    let (mut context, transport) = canonical_read_context(vec![
        effective_permission_page(&["CanA", "CanB"], Some("permissions-next")),
        effective_permission_page(&["CanC"], None),
    ]);
    let account = context.config.account.to_string();
    Args::try_parse_from([
        "iroha",
        "account",
        "permission",
        "list",
        "--id",
        &account,
        "--limit",
        "2",
        "--all",
        "--sort",
        "name",
        "--select",
        "name,payload",
    ])
    .unwrap()
    .command
    .run(&mut context)
    .unwrap();
    let page: iroha::collections::Page<Permission> =
        norito::json::from_json(context.output.as_deref().unwrap()).unwrap();
    assert_eq!(
        page.items.iter().map(Permission::name).collect::<Vec<_>>(),
        vec!["CanA", "CanB", "CanC"]
    );
    assert!(!page.has_more());
    let requests = transport.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    for (index, request) in requests.iter().enumerate() {
        assert_eq!(request.method, iroha::http::Method::POST);
        assert!(request.url.path().ends_with("/permissions/query"));
        assert!(request.url.query().is_none());
        let query = iroha::collections::ListQuery::from_json_value(
            norito::json::from_slice(&request.body).unwrap(),
        )
        .unwrap();
        assert_eq!(query.limit, Some(2));
        assert_eq!(
            query.cursor.as_deref(),
            (index == 1).then_some("permissions-next")
        );
        assert!(query.select.is_some());
        assert_eq!(query.sort.len(), 1);
    }
}
#[test]
fn account_permission_list_rejects_failed_or_non_effective_pages_without_output() {
    for damage in 0..5 {
        let mut damaged = effective_permission_page(&["CanB"], None);
        match damage {
            0 => {
                damaged
                    .headers_mut()
                    .remove("x-iroha-account-permission-semantics");
            }
            1 => {
                damaged.headers_mut().insert(
                    "x-iroha-account-permission-semantics",
                    "direct-only".parse().unwrap(),
                );
            }
            2 => {
                damaged.headers_mut().append(
                    "x-iroha-account-permission-semantics",
                    "effective-v1".parse().unwrap(),
                );
            }
            3 => {
                *damaged.body_mut() = br#"{"items":[],"total":1}"#.to_vec();
            }
            4 => {
                *damaged.status_mut() = iroha::http::StatusCode::CONFLICT;
            }
            _ => unreachable!(),
        }
        let (mut context, transport) = canonical_read_context(vec![
            effective_permission_page(&["CanA"], Some("permissions-next")),
            damaged,
        ]);
        let account = context.config.account.to_string();
        let result = Args::try_parse_from([
            "iroha",
            "account",
            "permission",
            "list",
            "--id",
            &account,
            "--limit",
            "1",
            "--all",
        ])
        .unwrap()
        .command
        .run(&mut context);
        assert!(result.is_err(), "damage {damage}");
        assert!(
            context.output.is_none(),
            "no partial permission set may escape"
        );
        assert_eq!(transport.requests.lock().unwrap().len(), 2);
    }
}
#[test]
fn account_permission_list_rejects_zero_limit_before_http() {
    let (mut context, transport) = canonical_read_context(Vec::new());
    let account = context.config.account.to_string();
    let result = Args::try_parse_from([
        "iroha",
        "account",
        "permission",
        "list",
        "--id",
        &account,
        "--limit",
        "0",
    ])
    .unwrap()
    .command
    .run(&mut context);
    assert!(result.is_err());
    assert!(transport.requests.lock().unwrap().is_empty());
    for flag in ["--offset", "--fetch-size", "--count-mode"] {
        assert!(
            Args::try_parse_from([
                "iroha",
                "account",
                "permission",
                "list",
                "--id",
                &account,
                flag,
                "1",
            ])
            .is_err()
        );
    }
}
#[test]
fn account_permission_list_propagates_server_page_cap_rejection() {
    let response = iroha::http::Response::builder()
        .status(400)
        .header("content-type", "application/json")
        .body(
            br#"{"code":"invalid_limit","message":"page limit exceeds server bound","details":{}}"#
                .to_vec(),
        )
        .unwrap();
    let (mut context, transport) = canonical_read_context(vec![response]);
    let account = context.config.account.to_string();
    let result = Args::try_parse_from([
        "iroha",
        "account",
        "permission",
        "list",
        "--id",
        &account,
        "--limit",
        "1000",
    ])
    .unwrap()
    .command
    .run(&mut context);
    assert!(result.is_err());
    assert!(context.output.is_none());
    assert_eq!(transport.requests.lock().unwrap().len(), 1);
}
#[test]
fn ledger_asset_get_uses_exact_singular_query_and_preserves_missing_asset_diagnostic() {
    use iroha::data_model::asset::AssetBalanceScope;
    use iroha::data_model::query::{
        QueryRequest, QueryResponse, SignedQuery, SingularQueryBox, SingularQueryOutputBox,
    };
    use iroha_version::codec::DecodeVersioned;

    for scope in [
        AssetBalanceScope::Global,
        AssetBalanceScope::Dataspace(DataSpaceId::new(3)),
    ] {
        for missing in [false, true] {
            let account = fallback_config().account;
            let definition = AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "coin".parse().unwrap(),
            );
            let id = AssetId::with_scope(definition.clone(), account.clone(), scope);
            let asset = Asset::new(id.clone(), 77_u32);
            let capabilities = iroha::http::Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(
                    format!(
                        "{{\"data_model_version\":{}}}",
                        iroha::data_model::DATA_MODEL_VERSION
                    )
                    .into_bytes(),
                )
                .unwrap();
            let response = if missing {
                let failure = iroha::data_model::query::error::QueryExecutionFail::Find(
                    iroha::data_model::query::error::FindError::Asset(Box::new(id.clone())),
                );
                let envelope = iroha_torii_shared::ErrorEnvelope::new(
                    "query_validation_failed",
                    failure.to_string(),
                );
                iroha::http::Response::builder()
                    .status(404)
                    .header("content-type", "application/x-norito")
                    .body(norito::to_bytes(&envelope).unwrap())
                    .unwrap()
            } else {
                iroha::http::Response::builder()
                    .status(200)
                    .header("content-type", "application/x-norito")
                    .body(
                        norito::to_bytes(&QueryResponse::Singular(SingularQueryOutputBox::Asset(
                            asset.clone(),
                        )))
                        .unwrap(),
                    )
                    .unwrap()
            };
            let (mut context, transport) = canonical_read_context(vec![capabilities, response]);
            let definition_literal = definition.to_string();
            let account_literal = account.to_string();
            let scope_literal = match scope {
                AssetBalanceScope::Global => "global",
                AssetBalanceScope::Dataspace(_) => "dataspace:3",
            };
            let result = Args::try_parse_from([
                "iroha",
                "ledger",
                "asset",
                "get",
                "--definition",
                &definition_literal,
                "--account",
                &account_literal,
                "--scope",
                scope_literal,
            ])
            .unwrap()
            .command
            .run(&mut context);
            let requests = transport.requests.lock().unwrap();
            assert_eq!(
                requests.len(),
                2,
                "only capability and singular query requests"
            );
            assert_eq!(requests[1].method, iroha::http::Method::POST);
            assert_eq!(requests[1].url.path(), "/v1/query");
            let signed = SignedQuery::decode_all_versioned(&requests[1].body).unwrap();
            signed.verify_signature().unwrap();
            assert_eq!(signed.authority(), &account);
            let QueryRequest::Singular(SingularQueryBox::FindAssetById(query)) = signed.request()
            else {
                panic!("asset get must submit the singular query, never an iterable scan");
            };
            assert_eq!(query.asset_id(), &id);
            if missing {
                let error = result.expect_err("singular missing asset must remain an error");
                let expected = iroha::data_model::query::error::QueryExecutionFail::Find(
                    iroha::data_model::query::error::FindError::Asset(Box::new(id.clone())),
                )
                .to_string();
                let Some(iroha::query::QueryError::Http {
                    status,
                    code,
                    message,
                }) = error.downcast_ref::<iroha::query::QueryError>()
                else {
                    panic!("expected typed HTTP query error, got {error:?}");
                };
                assert_eq!(*status, iroha::http::StatusCode::NOT_FOUND);
                assert_eq!(code, "query_validation_failed");
                assert_eq!(message, &expected);
                let rendered = format!("{error:#}");
                assert!(rendered.contains("HTTP 404"));
                assert!(rendered.contains("query_validation_failed"));
                assert!(rendered.contains(&expected));
                assert!(!rendered.contains("live query store"));
                assert!(context.output.is_none());
            } else {
                result.unwrap();
                let found: Asset =
                    norito::json::from_json(context.output.as_deref().unwrap()).unwrap();
                assert_eq!(found, asset);
            }
        }
    }
}

#[test]
fn transaction_submission_receipt_hash_roundtrips_through_status_cli() {
    use iroha::data_model::{nexus::FeeDebitSource, transaction::TransactionBuilder};
    use iroha_torii_shared::{FeeQuoteDecision, FeeQuoteObservation};

    let config = fallback_config();
    let fee_payment = FeePaymentIntent::authority(Vec::new(), None);
    let transaction = TransactionBuilder::new(
        config.network_id,
        config.account.clone(),
        fee_payment.clone(),
    )
    .with_instructions([Log::new(
        Level::INFO,
        "submission receipt fixture".to_owned(),
    )])
    .try_sign(config.key_pair.private_key())
    .expect("signed submission fixture");
    let hash = transaction.hash();
    let fee_quote = FeeQuoteResponse {
        intent: fee_payment,
        observation: FeeQuoteObservation {
            ledger_time_ms: 1,
            next_block_height: 2,
            route_dataspace_id: DataSpaceId::UNIVERSAL,
        },
        components: Vec::new(),
        capacities: Vec::new(),
        decision: FeeQuoteDecision::Accepted {
            debit_source: FeeDebitSource::Account(config.account),
            program_revision: None,
        },
    };
    let receipt = json_utils::json_object(
        transaction_submission_receipt_fields(hash, &transaction, &fee_quote).unwrap(),
    )
    .unwrap();
    let encoded = norito::json::to_json(&receipt).unwrap();
    let exported: json::Value = norito::json::from_json(&encoded).unwrap();
    let exported_hash = exported.get("hash").and_then(json::Value::as_str).unwrap();
    assert_eq!(exported_hash, hex::encode(hash.as_ref()));
    assert_eq!(exported_hash.len(), 64);
    assert!(
        exported_hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    let args = Args::try_parse_from(["iroha", "tx", "status", "--hash", exported_hash, "--wait"])
        .expect("the exported receipt hash must be accepted directly by tx status");
    let Command::Tx(transaction::Command::Status(status)) = args.command else {
        panic!("expected tx status");
    };
    assert_eq!(status.hash, hash);
    assert!(status.wait.wait);
    assert_eq!(
        exported.get("transaction"),
        Some(&json_utils::json_value(&transaction).unwrap())
    );
    assert_eq!(
        exported.get("fee_quote"),
        Some(&json_utils::json_value(&fee_quote).unwrap())
    );
    let checked_network = json_utils::json_value(&config.network_id).unwrap();
    assert!(checked_network.as_str().unwrap().starts_with("hash:"));
    assert_eq!(
        norito::json::from_value::<NetworkId>(checked_network).unwrap(),
        config.network_id
    );
    let checked_hash = json_utils::json_value(&hash).unwrap();
    assert!(
        Args::try_parse_from([
            "iroha",
            "tx",
            "status",
            "--hash",
            checked_hash.as_str().unwrap(),
        ])
        .is_err(),
        "the raw transaction locator parser must not gain a checked-literal fallback"
    );
}

fn diagnostics_fixture() -> iroha::data_model::block::consensus::SumeragiDiagnosticsStatus {
    use iroha::data_model::block::consensus::{SumeragiDiagnosticsStatus, SumeragiLaneGovernance};
    SumeragiDiagnosticsStatus {
        tx_queue_depth: 7,
        tx_queue_capacity: 20,
        tx_queue_retained_bytes: 3_072,
        tx_queue_max_retained_bytes: 4_096,
        tx_queue_saturated: true,
        tx_queue_saturated_by_count: false,
        tx_queue_saturated_by_bytes: true,
        tx_queue_saturated_by_age: false,
        tx_queue_oldest_queued_age_ms: 1_250,
        npos: None,
        lane_governance_sealed_total: 1,
        lane_governance_sealed_aliases: vec!["missing-manifest".to_owned()],
        lane_governance: [false, true]
            .into_iter()
            .enumerate()
            .map(|(index, ready)| SumeragiLaneGovernance {
                lane_id: iroha_model_base::topology::LaneId::new(
                    u32::try_from(index).expect("two fixture lanes"),
                ),
                alias: if ready { "ready" } else { "missing-manifest" }.to_owned(),
                governance: Some("operator-fixture".to_owned()),
                manifest_required: true,
                manifest_ready: ready,
                manifest_path: None,
                validator_ids: Vec::new(),
                quorum: None,
                protected_namespaces: Vec::new(),
                runtime_upgrade: None,
            })
            .collect(),
    }
}

fn diagnostics_context() -> (CanonicalReadContext, std::sync::Arc<CanonicalReadTransport>) {
    let response = iroha::http::Response::builder()
        .status(200)
        .header("content-type", "application/x-norito")
        .body(norito::encode_canonical(&diagnostics_fixture()).unwrap())
        .unwrap();
    let (mut context, transport) = canonical_read_context(vec![response]);
    // An embedded SDK key must never replace the command's explicit authority.
    let mut builder = context.client.to_builder();
    builder.operator_key_pair = Some(fixture_key_pair(0x72));
    context.client = builder.build().unwrap();
    (context, transport)
}

fn assert_missing_operator_authority(arguments: &[&str]) {
    let (mut context, transport) = diagnostics_context();
    let error = Args::try_parse_from(arguments)
        .unwrap()
        .command
        .run(&mut context)
        .expect_err("operator reads require the configured CLI operator authority");
    assert!(error.to_string().contains("--operator-private-key-file"));
    assert!(context.output.is_none());
    assert!(transport.requests.lock().unwrap().is_empty());
    assert_eq!(transport.responses.lock().unwrap().len(), 1);
}

fn assert_exact_operator_request(
    context: &CanonicalReadContext,
    transport: &CanonicalReadTransport,
    operator: &KeyPair,
) {
    use base64::Engine as _;
    let requests = transport.requests.lock().unwrap();
    assert_eq!(requests.len(), 1, "no capability probe or request replay");
    let request = &requests[0];
    assert_eq!(request.method, iroha::http::Method::GET);
    assert_eq!(request.url.path(), "/v1/sumeragi/diagnostics");
    assert!(request.url.query().is_none());
    assert!(request.body.is_empty());
    let header = |name: &str| {
        let values: Vec<_> = request
            .headers
            .iter()
            .filter(|(key, _)| key == name)
            .collect();
        assert_eq!(values.len(), 1, "exactly one {name}");
        values[0].1.to_str().unwrap()
    };
    let public_key: iroha::crypto::PublicKey =
        header("x-iroha-operator-public-key").parse().unwrap();
    assert_eq!(&public_key, operator.public_key());
    assert_ne!(&public_key, context.config.key_pair.public_key());
    assert_ne!(&public_key, fixture_key_pair(0x72).public_key());
    let signature = iroha::crypto::Signature::from_bytes(
        &base64::engine::general_purpose::STANDARD
            .decode(header("x-iroha-operator-signature"))
            .unwrap(),
    );
    let message = Client::operator_network_request_message(
        &context.config.network_id,
        &request.method,
        &request.url,
        &request.body,
        header("x-iroha-operator-timestamp-ms").parse().unwrap(),
        header("x-iroha-operator-nonce"),
    )
    .unwrap();
    signature.verify(operator.public_key(), &message).unwrap();
    assert!(
        signature
            .verify(context.config.key_pair.public_key(), &message)
            .is_err()
    );
    for name in [
        "x-iroha-account",
        "x-iroha-signature",
        "x-iroha-witness",
        "authorization",
    ] {
        assert!(!request.headers.iter().any(|(key, _)| key == name));
    }
    assert!(transport.responses.lock().unwrap().is_empty());
}

#[test]
fn sumeragi_diagnostics_requires_explicit_operator_before_io() {
    assert_missing_operator_authority(&["iroha", "ops", "sumeragi", "diagnostics"]);
}

#[test]
fn nexus_lane_report_requires_explicit_operator_before_io() {
    assert_missing_operator_authority(&["iroha", "app", "nexus", "lane-report"]);
}

#[test]
fn sumeragi_diagnostics_signs_with_cli_operator_and_preserves_typed_response() {
    let (mut context, transport) = diagnostics_context();
    let operator = fixture_key_pair(0x73);
    context.operator_key_pair = Some(operator.clone());
    Args::try_parse_from(["iroha", "ops", "sumeragi", "diagnostics"])
        .unwrap()
        .command
        .run(&mut context)
        .unwrap();
    let actual: iroha::data_model::block::consensus::SumeragiDiagnosticsStatus =
        norito::json::from_json(context.output.as_deref().unwrap()).unwrap();
    assert_eq!(actual, diagnostics_fixture());
    assert_exact_operator_request(&context, &transport, &operator);
}

#[test]
fn nexus_lane_report_signs_with_cli_operator_and_preserves_sealed_failure() {
    let (mut context, transport) = diagnostics_context();
    let operator = fixture_key_pair(0x74);
    context.operator_key_pair = Some(operator.clone());
    let error = Args::try_parse_from([
        "iroha",
        "app",
        "nexus",
        "lane-report",
        "--only-missing",
        "--fail-on-sealed",
    ])
    .unwrap()
    .command
    .run(&mut context)
    .expect_err("the authenticated report must still reject sealed lanes");
    assert!(error.to_string().contains("1 lane(s) still sealed"));
    let actual: norito::json::Value =
        norito::json::from_json(context.output.as_deref().unwrap()).unwrap();
    assert_eq!(
        actual
            .get("sealed_total")
            .and_then(norito::json::Value::as_u64),
        Some(1)
    );
    assert_eq!(
        actual.get("sealed_aliases"),
        Some(&norito::json::to_value(&vec!["missing-manifest"]).unwrap())
    );
    assert_eq!(
        actual.get("lanes"),
        Some(
            &norito::json::to_value(&vec![diagnostics_fixture().lane_governance.remove(0)])
                .unwrap()
        )
    );
    assert_exact_operator_request(&context, &transport, &operator);
}

fn staking_preparation_fixture() -> iroha::data_model::nexus::PublicLanePreparationV1 {
    use iroha::data_model::{asset::AssetId, nexus::*, parameter::system::SumeragiNposParameters};
    use iroha_model_base::{peer::PeerId, topology::LaneId};

    let config = fallback_config();
    let xor = SumeragiNposParameters::default().xor_asset_definition_id;
    let source = AssetId::of(xor.clone(), config.account.clone());
    let destination = AssetId::of(xor.clone(), iroha_test_samples::BOB_ID.clone());
    let amount: iroha_primitives::numeric::Quantity = "10.000000001".parse().unwrap();
    let plan = PublicLaneMonetaryPlanV1 {
        network_scope: PublicLaneMonetaryScopeV1::Network(config.network_id),
        valid_until_height: 15,
        source_asset: source.clone(),
        destination_asset: destination.clone(),
        amount: amount.clone(),
        precondition: PublicLaneMonetaryPreconditionV1::Registration(
            PublicLaneMonetaryRegistrationV1 {
                activation_height: 21,
            },
        ),
    };
    assert!(plan.has_canonical_shape());
    let mut balances = vec![
        PublicLanePreparationBalanceV1 {
            asset: source,
            balance: 100_u64.into(),
            stake_reserved: 2_u64.into(),
            rewards_reserved: 3_u64.into(),
        },
        PublicLanePreparationBalanceV1 {
            asset: destination,
            balance: 200_u64.into(),
            stake_reserved: 4_u64.into(),
            rewards_reserved: 5_u64.into(),
        },
    ];
    balances.sort_by(|left, right| left.asset.cmp(&right.asset));
    PublicLanePreparationV1 {
        request: PublicLanePreparationRequestV1 {
            lane_id: LaneId::SINGLE,
            valid_for_blocks: 10,
            operation: PublicLanePreparationOperationV1::Registration(
                PublicLanePrepareRegistrationV1 {
                    validator: config.account,
                    peer_id: PeerId::new(
                        KeyPair::try_from_seed(vec![0x51; 32], Algorithm::BlsNormal)
                            .unwrap()
                            .public_key()
                            .clone(),
                    ),
                    amount,
                    candidate: false,
                },
            ),
        },
        network_id: config.network_id,
        observed_height: 5,
        observed_block_hash: Hash::new(b"CLI staking observation"),
        observed_ledger_time_ms: 123,
        assumed_execution_height: 6,
        xor_asset_definition_id: xor,
        plan: PublicLanePreparedPlanV1::Monetary(plan),
        balances,
    }
}

#[test]
fn staking_prepare_dispatch_preserves_exact_plan_tip_and_both_reserves() {
    let prepared = staking_preparation_fixture();
    let file = NamedTempFile::new().unwrap();
    fs::write(
        file.path(),
        norito::json::to_json(&prepared.request).unwrap(),
    )
    .unwrap();
    for substituted_network in [false, true] {
        let mut response = prepared.clone();
        if substituted_network {
            response.network_id = iroha::data_model::NetworkId::from_genesis_hash(
                iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(b"foreign preparation")),
            );
        }
        let response = iroha::http::Response::builder()
            .status(200)
            .header("content-type", "application/x-norito")
            .body(norito::encode_canonical(&response).unwrap())
            .unwrap();
        let (mut context, transport) = canonical_read_context(vec![response]);
        let result = Args::try_parse_from([
            "iroha",
            "app",
            "staking",
            "prepare",
            "--request",
            file.path().to_str().unwrap(),
        ])
        .unwrap()
        .command
        .run(&mut context);
        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, iroha::http::Method::POST);
        assert_eq!(requests[0].url.path(), "/v1/nexus/staking/prepare");
        assert_eq!(
            requests[0].body,
            norito::encode_canonical(&prepared.request).unwrap()
        );
        assert!(
            context.submitted.is_none(),
            "preparation never signs or submits"
        );
        if substituted_network {
            assert!(result.is_err());
            assert!(
                context.output.is_none(),
                "substituted plans are not displayed"
            );
        } else {
            result.unwrap();
            assert_eq!(
                context.output,
                Some(norito::json::to_json(&prepared).unwrap())
            );
        }
    }
}

#[test]
fn staking_prepare_rejects_missing_unknown_and_retired_request_fields_before_http() {
    let request = norito::json::to_value(&staking_preparation_fixture().request).unwrap();
    for mutation in 0..5 {
        let mut malformed = request.clone();
        let fields = malformed.as_object_mut().unwrap();
        match mutation {
            0 => {
                fields.remove("operation");
            }
            1 => {
                fields.remove("valid_for_blocks");
            }
            2 => {
                fields.insert("automatic_amount".into(), json::Value::Bool(true));
            }
            3 => {
                fields
                    .get_mut("operation")
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .get_mut("value")
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .remove("candidate");
            }
            4 => {
                fields
                    .get_mut("operation")
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .get_mut("value")
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .insert("fee_from_principal".into(), json::Value::Bool(true));
            }
            _ => unreachable!(),
        }
        let file = NamedTempFile::new().unwrap();
        fs::write(file.path(), norito::json::to_json(&malformed).unwrap()).unwrap();
        let (mut context, transport) = canonical_read_context(vec![]);
        assert!(
            Args::try_parse_from([
                "iroha",
                "app",
                "staking",
                "prepare",
                "--request",
                file.path().to_str().unwrap(),
            ])
            .unwrap()
            .command
            .run(&mut context)
            .is_err(),
            "mutation {mutation}"
        );
        assert!(transport.requests.lock().unwrap().is_empty());
        assert!(context.output.is_none());
        assert!(context.submitted.is_none());
    }
}

fn committee_observation_fixture() -> iroha::data_model::nexus::ValidatorCommitteeStatusV1 {
    use iroha::data_model::{
        block::{BlockHeader, builder::BlockBuilder},
        nexus::ValidatorCommitteeStatusV1,
        sumeragi::finality::{NativeFinalityArtifact, NativeFinalityLimits},
    };
    let config = fallback_config();
    // A transport observation, not an authenticated finality fixture. Core owns
    // verification of the native chain; the CLI must preserve the original frame.
    let transaction = TransactionBuilder::new(
        config.network_id,
        config.account,
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .try_sign(config.key_pair.private_key())
    .unwrap();
    let mut block = BlockBuilder::new(BlockHeader::new(
        NonZeroU64::new(2).unwrap(),
        Some(iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(
            b"CLI predecessor",
        ))),
        None,
        10,
        0,
    ));
    block.push_transaction(transaction);
    let block = block
        .try_build_with_signature(0, config.key_pair.private_key())
        .unwrap();
    ValidatorCommitteeStatusV1 {
        network_id: config.network_id,
        target_epoch: 7,
        latest_finality: NativeFinalityArtifact::from_block(
            &block,
            NativeFinalityLimits {
                block_bytes: 16 * 1024 * 1024,
                journal_bytes: 16 * 1024 * 1024,
                block_count: 256,
                allocated_bytes: 64 * 1024 * 1024,
            },
        )
        .unwrap(),
        selected: None,
        pending_beacon_session: None,
    }
}

#[test]
fn committee_status_dispatch_preserves_original_finality_and_absent_preparation() {
    let status = committee_observation_fixture();
    let response = iroha::http::Response::builder()
        .status(200)
        .header("content-type", "application/x-norito")
        .body(norito::encode_canonical(&status).unwrap())
        .unwrap();
    let (mut context, transport) = canonical_read_context(vec![response]);
    Args::try_parse_from([
        "iroha",
        "app",
        "nexus",
        "public-lane",
        "committee-status",
        "--target-epoch",
        "7",
    ])
    .unwrap()
    .command
    .run(&mut context)
    .unwrap();
    assert_eq!(
        context.output,
        Some(norito::json::to_json(&status).unwrap())
    );
    assert!(context.submitted.is_none());
    let requests = transport.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, iroha::http::Method::GET);
    assert_eq!(requests[0].url.path(), "/v1/nexus/validator-committee");
    assert_eq!(requests[0].url.query(), Some("target_epoch=7"));
    assert!(requests[0].body.is_empty());
}

#[test]
fn staking_workflow_commands_require_explicit_inputs_without_legacy_aliases() {
    for args in [
        vec!["iroha", "app", "staking", "prepare"],
        vec!["iroha", "app", "nexus", "public-lane", "committee-submit"],
        vec!["iroha", "app", "nexus", "public-lane", "committee-status"],
        vec![
            "iroha",
            "app",
            "nexus",
            "public-lane",
            "committee-status",
            "--target-epoch",
            "0",
        ],
        vec!["iroha", "app", "nexus", "public-lane", "committee-activate"],
        vec!["iroha", "app", "nexus", "public-lane", "committee-cancel"],
        vec!["iroha", "staking", "prepare", "--request", "intent.json"],
    ] {
        assert!(Args::try_parse_from(&args).is_err(), "{args:?}");
    }
}

fn committee_operations_fixture() -> Vec<iroha::data_model::nexus::ValidatorCommitteeOperationV1> {
    use iroha::data_model::{
        consensus::{
            GlobalThresholdBeaconPartialSignatureProofV1, GlobalThresholdBeaconPartialSignatureV1,
        },
        nexus::*,
        sumeragi::epoch::InstalledBeaconEpochBindingV1,
    };
    // Structural command-dispatch fixtures. Their bytes are never submitted to
    // a network; Core tests own cryptographic possession and finality verification.
    vec![
        ValidatorCommitteeOperationV1::PrepareCredentials(PrepareValidatorCommitteeCredentialsV1 {
            transition_id: [7; 32],
            target_epoch: 2,
            credentials: ValidatorCommitteeCredentialsV1 {
                beacon: InstalledBeaconEpochBindingV1 {
                    session_id: [8; 32],
                    transcript_hash: [9; 32],
                },
            },
        }),
        ValidatorCommitteeOperationV1::AdmitSeat(AdmitValidatorCommitteeSeatV1 {
            transition_id: [7; 32],
            target_epoch: 2,
            readiness: ValidatorCommitteeSeatReadinessV1 {
                validator_index: 0,
                beacon: GlobalThresholdBeaconPartialSignatureV1 {
                    session_id: [8; 32],
                    signer_index: 1,
                    signature_share: [10; 48],
                    proof: GlobalThresholdBeaconPartialSignatureProofV1 {
                        x: [11; 96],
                        y: [12; 48],
                        z_s: [13; 32],
                        z_r: [14; 32],
                        z_u: [15; 32],
                    },
                },
            },
        }),
    ]
}

#[test]
fn committee_submit_dispatch_preserves_every_exact_reviewed_operation() {
    use iroha::data_model::{
        isi::SetParameter, nexus::ValidatorCommitteeOperationV1, parameter::Parameter,
        sumeragi::epoch::MAX_VALIDATORS,
    };

    let mut operations = committee_operations_fixture();
    let mut maximum_seat = operations
        .iter()
        .find_map(|operation| match operation {
            ValidatorCommitteeOperationV1::AdmitSeat(value) => Some(value.clone()),
            _ => None,
        })
        .unwrap();
    maximum_seat.readiness.validator_index = u32::try_from(MAX_VALIDATORS - 1).unwrap();
    maximum_seat.readiness.beacon.signer_index = u16::try_from(MAX_VALIDATORS).unwrap();
    operations.push(ValidatorCommitteeOperationV1::AdmitSeat(maximum_seat));
    for operation in operations {
        let file = NamedTempFile::new().unwrap();
        fs::write(file.path(), norito::json::to_json(&operation).unwrap()).unwrap();
        let (mut context, transport) = canonical_read_context(vec![]);
        Args::try_parse_from([
            "iroha",
            "app",
            "nexus",
            "public-lane",
            "committee-submit",
            "--file",
            file.path().to_str().unwrap(),
        ])
        .unwrap()
        .command
        .run(&mut context)
        .unwrap();
        let expected: InstructionBox =
            SetParameter::new(Parameter::Custom(operation.into_custom_parameter())).into();
        assert_eq!(context.submitted, Some(vec![expected]));
        assert!(context.output.is_none());
        assert!(
            transport.requests.lock().unwrap().is_empty(),
            "use existing signing flow without a discovery probe"
        );
    }
}

#[test]
fn committee_submit_rejects_missing_and_unknown_fields_before_signing() {
    use iroha::data_model::nexus::ValidatorCommitteeOperationV1;
    for operation in committee_operations_fixture() {
        let mut variants = Vec::new();
        let original = norito::json::to_value(&operation).unwrap();
        if let ValidatorCommitteeOperationV1::AdmitSeat(admission) = &operation {
            let proof_bytes = iroha_crypto::threshold_bls::THRESHOLD_BLS_PUBLIC_KEY_BYTES;
            assert_eq!(admission.readiness.beacon.proof.x.len(), proof_bytes);
            for length in [proof_bytes - 1, proof_bytes + 1] {
                let mut malformed = original.clone();
                malformed
                    .as_object_mut()
                    .unwrap()
                    .get_mut("value")
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .get_mut("readiness")
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .get_mut("beacon")
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .get_mut("proof")
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .insert(
                        "x".into(),
                        json::Value::Array(vec![json::Value::from(11_u64); length]),
                    );
                let file = NamedTempFile::new().unwrap();
                fs::write(file.path(), norito::json::to_json(&malformed).unwrap()).unwrap();
                let error = crate::staking::load_committee_json(file.path(), "--file").unwrap_err();
                if length > proof_bytes {
                    assert!(error.to_string().contains("JSON resource bounds"));
                } else {
                    assert!(
                        error
                            .to_string()
                            .contains("valid Norito JSON staking object")
                    );
                }
                variants.push(malformed);
            }
        }
        for missing in ["kind", "value"] {
            let mut value = original.clone();
            value.as_object_mut().unwrap().remove(missing);
            variants.push(value);
        }
        let mut unknown = original.clone();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("compatibility".into(), json::Value::Bool(true));
        variants.push(unknown);
        let mut unknown = original.clone();
        unknown
            .as_object_mut()
            .unwrap()
            .get_mut("value")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("retired_epoch_staging".into(), json::Value::Null);
        variants.push(unknown);
        let mut unknown = original.clone();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("kind".into(), json::Value::String("Activate".into()));
        variants.push(unknown);
        for malformed in variants {
            let file = NamedTempFile::new().unwrap();
            fs::write(file.path(), norito::json::to_json(&malformed).unwrap()).unwrap();
            let (mut context, transport) = canonical_read_context(vec![]);
            assert!(
                Args::try_parse_from([
                    "iroha",
                    "app",
                    "nexus",
                    "public-lane",
                    "committee-submit",
                    "--file",
                    file.path().to_str().unwrap(),
                ])
                .unwrap()
                .command
                .run(&mut context)
                .is_err()
            );
            assert!(
                context.submitted.is_none(),
                "malformed operation must not reach signing"
            );
            assert!(transport.requests.lock().unwrap().is_empty());
        }
    }
}

#[test]
fn contract_history_commands_use_shared_collection_controls() {
    for command in ["activity", "events"] {
        let reply = iroha::http::Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(br#"{"items":[],"next_cursor":null}"#.to_vec())
            .unwrap();
        let (mut context, transport) = canonical_read_context(vec![reply]);
        Args::try_parse_from([
            "iroha",
            "contract",
            command,
            "--filter",
            "block_height >= 7",
            "--limit",
            "2",
        ])
        .unwrap()
        .command
        .run(&mut context)
        .unwrap();
        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, iroha::http::Method::POST);
        assert_eq!(
            requests[0].url.path(),
            format!("/v1/contracts/{command}/query")
        );
        assert!(context.output.is_some());
    }
}

#[test]
fn explorer_and_account_history_commands_use_shared_query_pages() {
    for (command, path) in [
        (vec!["account", "history"], "history"),
        (vec!["explorer", "accounts"], "accounts"),
        (vec!["explorer", "domains"], "domains"),
        (vec!["explorer", "asset-definitions"], "asset-definitions"),
        (vec!["explorer", "assets"], "assets"),
        (vec!["explorer", "nfts"], "nfts"),
        (vec!["explorer", "rwas"], "rwas"),
        (vec!["explorer", "blocks"], "blocks"),
        (vec!["explorer", "transactions"], "transactions"),
        (
            vec!["explorer", "transactions-latest"],
            "transactions/latest",
        ),
        (vec!["explorer", "instructions"], "instructions"),
        (
            vec!["explorer", "instructions-latest"],
            "instructions/latest",
        ),
    ] {
        let reply = iroha::http::Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(br#"{"items":[],"next_cursor":null}"#.to_vec())
            .unwrap();
        let (mut context, transport) = canonical_read_context(vec![reply]);
        let mut args = vec!["iroha"];
        args.extend(command);
        args.extend(["--limit", "2"]);
        Args::try_parse_from(args)
            .unwrap()
            .command
            .run(&mut context)
            .unwrap();
        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, iroha::http::Method::POST);
        assert!(requests[0].url.path().ends_with(&format!("/{path}/query")));
        assert!(context.output.is_some());
    }
}
