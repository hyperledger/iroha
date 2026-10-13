//! Cross-runtime local SoraFS parity against the actual Node module and C ABI.
#[cfg(feature = "js_host_parity")]
mod js_host_parity {
    use norito::{json, json::Value};
    use sorafs_car::{
        fetch_plan::{chunk_fetch_plan_to_string, try_chunk_fetch_plan_to_json},
        fixtures::MultiPeerFixture,
        local_fetch::{
            self, LocalFetchOptions, LocalFetchScoreboardEntry, LocalProviderInput,
            ProviderMetadataInput,
        },
    };
    use std::{
        collections::HashMap,
        path::Path,
        process::Command,
        time::{Duration, Instant},
    };
    use tempfile::tempdir;
    fn providers_json_from_metadata(
        metadata: &sorafs_car::multi_fetch::ProviderMetadata,
        path: &Path,
    ) -> norito::json::Value {
        let mut obj = norito::json::Map::new();
        obj.insert(
            "name".into(),
            norito::json::Value::from(metadata.provider_id.clone().unwrap()),
        );
        obj.insert(
            "path".into(),
            norito::json::Value::from(path.to_string_lossy().to_string()),
        );
        obj.insert("max_concurrent".into(), norito::json::Value::from(2u32));
        obj.insert("weight".into(), norito::json::Value::from(1u32));
        let meta = ProviderMetadataInput::from_metadata(metadata);
        let mut meta_obj = norito::json::Map::new();
        if let Some(id) = meta.provider_id {
            meta_obj.insert("provider_id".into(), norito::json::Value::from(id));
        }
        if let Some(profile) = meta.profile_id {
            meta_obj.insert("profile_id".into(), norito::json::Value::from(profile));
        }
        if let Some(aliases) = meta.profile_aliases {
            let alias_values = aliases
                .into_iter()
                .map(norito::json::Value::from)
                .collect::<Vec<_>>();
            meta_obj.insert(
                "profile_aliases".into(),
                norito::json::Value::Array(alias_values),
            );
        }
        if let Some(availability) = meta.availability {
            meta_obj.insert(
                "availability".into(),
                norito::json::Value::from(availability),
            );
        }
        if let Some(stake) = meta.stake_amount {
            meta_obj.insert("stake_amount".into(), norito::json::Value::from(stake));
        }
        if let Some(max_streams) = meta.max_streams {
            meta_obj.insert(
                "max_streams".into(),
                norito::json::Value::from(u32::from(max_streams)),
            );
        }
        if let Some(refresh) = meta.refresh_deadline {
            meta_obj.insert(
                "refresh_deadline".into(),
                norito::json::Value::from(refresh),
            );
        }
        if let Some(expires_at) = meta.expires_at {
            meta_obj.insert("expires_at".into(), norito::json::Value::from(expires_at));
        }
        if let Some(ttl) = meta.ttl_secs {
            meta_obj.insert("ttl_secs".into(), norito::json::Value::from(ttl));
        }
        meta_obj.insert(
            "allow_unknown_capabilities".into(),
            norito::json::Value::from(meta.allow_unknown_capabilities.unwrap_or(false)),
        );
        if let Some(names) = meta.capability_names {
            let name_values = names
                .into_iter()
                .map(norito::json::Value::from)
                .collect::<Vec<_>>();
            meta_obj.insert(
                "capability_names".into(),
                norito::json::Value::Array(name_values),
            );
        }
        if let Some(topics) = meta.rendezvous_topics {
            let topic_values = topics
                .into_iter()
                .map(norito::json::Value::from)
                .collect::<Vec<_>>();
            meta_obj.insert(
                "rendezvous_topics".into(),
                norito::json::Value::Array(topic_values),
            );
        }
        if let Some(notes) = meta.notes {
            meta_obj.insert("notes".into(), norito::json::Value::from(notes));
        }
        if let Some(range) = meta.range_capability {
            let mut range_obj = norito::json::Map::new();
            range_obj.insert(
                "max_chunk_span".into(),
                norito::json::Value::from(range.max_chunk_span),
            );
            range_obj.insert(
                "min_granularity".into(),
                norito::json::Value::from(range.min_granularity),
            );
            range_obj.insert(
                "supports_sparse_offsets".into(),
                norito::json::Value::from(range.supports_sparse_offsets.unwrap_or(true)),
            );
            range_obj.insert(
                "requires_alignment".into(),
                norito::json::Value::from(range.requires_alignment.unwrap_or(false)),
            );
            range_obj.insert(
                "supports_merkle_proof".into(),
                norito::json::Value::from(range.supports_merkle_proof.unwrap_or(true)),
            );
            meta_obj.insert(
                "range_capability".into(),
                norito::json::Value::Object(range_obj),
            );
        }
        if let Some(budget) = meta.stream_budget {
            let mut budget_obj = norito::json::Map::new();
            budget_obj.insert(
                "max_in_flight".into(),
                norito::json::Value::from(budget.max_in_flight),
            );
            budget_obj.insert(
                "max_bytes_per_sec".into(),
                norito::json::Value::from(budget.max_bytes_per_sec),
            );
            if let Some(burst) = budget.burst_bytes {
                budget_obj.insert("burst_bytes".into(), norito::json::Value::from(burst));
            }
            meta_obj.insert(
                "stream_budget".into(),
                norito::json::Value::Object(budget_obj),
            );
        }
        if let Some(hints) = meta.transport_hints {
            let mut list = Vec::with_capacity(hints.len());
            for hint in hints {
                let mut obj = norito::json::Map::new();
                obj.insert("protocol".into(), norito::json::Value::from(hint.protocol));
                obj.insert(
                    "protocol_id".into(),
                    norito::json::Value::from(hint.protocol_id),
                );
                obj.insert("priority".into(), norito::json::Value::from(hint.priority));
                list.push(norito::json::Value::Object(obj));
            }
            meta_obj.insert("transport_hints".into(), norito::json::Value::Array(list));
        }
        obj.insert("metadata".into(), norito::json::Value::Object(meta_obj));
        norito::json::Value::Object(obj)
    }
    fn provider_input_from_metadata(
        metadata: &sorafs_car::multi_fetch::ProviderMetadata,
        path: &Path,
    ) -> LocalProviderInput {
        LocalProviderInput {
            name: metadata.provider_id.clone().unwrap(),
            path: path.to_path_buf(),
            max_concurrent: Some(2),
            weight: Some(1),
            metadata: Some(ProviderMetadataInput::from_metadata(metadata)),
        }
    }
    fn scoreboard_map_from_result(
        entries: Option<&[LocalFetchScoreboardEntry]>,
    ) -> HashMap<String, (f64, String)> {
        entries
            .into_iter()
            .flat_map(|entries| entries.iter())
            .map(|entry| {
                (
                    entry.alias.clone(),
                    (entry.normalized_weight, format!("{}", entry.eligibility)),
                )
            })
            .collect()
    }
    fn scoreboard_map_from_json(value: &norito::json::Value) -> HashMap<String, (f64, String)> {
        match value {
            norito::json::Value::Array(entries) => entries
                .iter()
                .filter_map(|entry| entry.as_object())
                .filter_map(|obj| {
                    let alias = obj.get("alias")?.as_str()?.to_owned();
                    let weight = obj.get("normalized_weight")?.as_f64()?;
                    let eligibility = obj.get("eligibility")?.as_str()?.to_owned();
                    Some((alias, (weight, eligibility)))
                })
                .collect(),
            _ => HashMap::new(),
        }
    }

    fn run_native_runtime(program: &str, script: &Path, request: &Path) -> Value {
        let output = Command::new(program)
            .arg(script)
            .arg(request)
            .output()
            .expect("launch actual native runtime");
        assert!(
            output.status.success(),
            "{program} native runtime failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.stdout.len() <= 16 * 1024 * 1024,
            "native report exceeds test bound"
        );
        norito::json::from_slice(&output.stdout).expect("canonical native runtime report")
    }
    fn duration_from_report(report: &Value) -> Duration {
        Duration::from_nanos(
            report
                .get("duration_ns")
                .and_then(Value::as_u64)
                .expect("actual native call duration"),
        )
    }
    fn reports_from_json(report: &Value) -> HashMap<String, (u64, u64, bool)> {
        report
            .get("provider_reports")
            .and_then(Value::as_array)
            .expect("provider reports")
            .iter()
            .map(|entry| {
                (
                    entry
                        .get("provider")
                        .and_then(Value::as_str)
                        .expect("provider id")
                        .to_owned(),
                    (
                        entry
                            .get("successes")
                            .and_then(Value::as_u64)
                            .expect("successes"),
                        entry
                            .get("failures")
                            .and_then(Value::as_u64)
                            .expect("failures"),
                        entry
                            .get("disabled")
                            .and_then(Value::as_bool)
                            .expect("disabled"),
                    ),
                )
            })
            .collect()
    }
    fn receipts_from_json(report: &Value) -> Vec<(u64, String, u64)> {
        report
            .get("chunk_receipts")
            .and_then(Value::as_array)
            .expect("chunk receipts")
            .iter()
            .map(|entry| {
                (
                    entry
                        .get("chunk_index")
                        .and_then(Value::as_u64)
                        .expect("chunk index"),
                    entry
                        .get("provider")
                        .and_then(Value::as_str)
                        .expect("provider id")
                        .to_owned(),
                    entry
                        .get("attempts")
                        .and_then(Value::as_u64)
                        .expect("attempts"),
                )
            })
            .collect()
    }
    #[test]
    fn orchestrator_parity_across_runtimes() {
        let fixture = MultiPeerFixture::with_providers(2).expect("canonical multi-peer fixture");
        let tempdir = tempdir().expect("tempdir");
        let directory = tempdir
            .path()
            .canonicalize()
            .expect("physical private fixture directory");
        let plan = fixture.plan();
        let plan_json = try_chunk_fetch_plan_to_json(plan).expect("canonical plan JSON");
        let plan_json_string = chunk_fetch_plan_to_string(plan).expect("canonical plan string");
        let mut local_inputs = Vec::new();
        let mut providers = Vec::new();
        for (idx, metadata) in fixture.providers().iter().enumerate() {
            let name = metadata.provider_id.clone().expect("provider id");
            let path = directory.join(format!("{name}.bin"));
            std::fs::write(&path, &fixture.provider_payloads()[idx]).expect("write payload");
            local_inputs.push(provider_input_from_metadata(metadata, &path));
            providers.push(providers_json_from_metadata(metadata, &path));
        }
        let local_options = LocalFetchOptions {
            verify_digests: Some(true),
            verify_lengths: Some(true),
            use_scoreboard: Some(true),
            return_scoreboard: Some(true),
            scoreboard_now_unix_secs: Some(fixture.now_unix_secs()),
            ..Default::default()
        };
        let rust_start = Instant::now();
        let baseline = local_fetch::execute_local_fetch(&plan_json, local_inputs, local_options)
            .expect("rust baseline");
        let rust_duration = rust_start.elapsed();
        let request = json!({
            "plan": plan_json_string,
            "providers": (Value::Array(providers)),
            "options": {
                "verify_digests": true, "verify_lengths": true, "use_scoreboard": true,
                "return_scoreboard": true, "scoreboard_now_unix_secs": (fixture.now_unix_secs()),
            },
        });
        let request_path = directory.join("runtime-request.json");
        std::fs::write(
            &request_path,
            norito::json::to_string(&request).expect("runtime request"),
        )
        .expect("write runtime request");
        let support = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support");
        let node = std::env::var("IROHA_PARITY_NODE").unwrap_or_else(|_| "node".to_owned());
        let python = std::env::var("IROHA_PARITY_PYTHON").unwrap_or_else(|_| "python3".to_owned());
        let js_result = run_native_runtime(
            &node,
            &support.join("sorafs_parity_node.mjs"),
            &request_path,
        );
        let js_duration = duration_from_report(&js_result);
        let js_report = js_result.get("report").expect("JS report");
        let js_payload = hex::decode(
            js_result
                .get("payload_hex")
                .and_then(Value::as_str)
                .expect("JS payload bytes"),
        )
        .expect("JS payload hex");
        assert_eq!(
            js_payload,
            baseline.outcome.assemble_payload(),
            "JS payload mismatch"
        );
        let rust_scoreboard = scoreboard_map_from_result(baseline.scoreboard.as_deref());
        let js_scoreboard =
            scoreboard_map_from_json(js_report.get("scoreboard").expect("JS scoreboard"));
        assert_eq!(rust_scoreboard, js_scoreboard, "JS scoreboard mismatch");
        let rust_reports: HashMap<_, _> = baseline
            .outcome
            .provider_reports
            .iter()
            .map(|report| {
                (
                    report.provider.id().as_str().to_owned(),
                    (
                        report.successes as u64,
                        report.failures as u64,
                        report.disabled,
                    ),
                )
            })
            .collect();
        assert_eq!(
            rust_reports,
            reports_from_json(js_report),
            "JS provider reports mismatch"
        );
        let rust_receipts: Vec<_> = baseline
            .outcome
            .chunk_receipts
            .iter()
            .map(|receipt| {
                (
                    receipt.chunk_index as u64,
                    receipt.provider.to_string(),
                    receipt.attempts as u64,
                )
            })
            .collect();
        assert_eq!(
            rust_receipts,
            receipts_from_json(js_report),
            "JS chunk receipts mismatch"
        );
        let ffi_result = run_native_runtime(
            &python,
            &support.join("sorafs_parity_ffi.py"),
            &request_path,
        );
        let ffi_duration = duration_from_report(&ffi_result);
        assert_eq!(
            ffi_result.get("return_code").and_then(Value::as_u64),
            Some(0),
            "FFI fetch returned error"
        );
        let ffi_payload = hex::decode(
            ffi_result
                .get("payload_hex")
                .and_then(Value::as_str)
                .expect("FFI payload bytes"),
        )
        .expect("FFI payload hex");
        assert_eq!(
            ffi_payload,
            baseline.outcome.assemble_payload(),
            "FFI payload mismatch"
        );
        let ffi_report = ffi_result.get("report").expect("FFI report");
        let ffi_scoreboard =
            scoreboard_map_from_json(ffi_report.get("scoreboard").expect("FFI scoreboard"));
        assert_eq!(rust_scoreboard, ffi_scoreboard, "FFI scoreboard mismatch");
        assert_eq!(
            rust_reports,
            reports_from_json(ffi_report),
            "FFI provider reports mismatch"
        );
        assert_eq!(
            rust_receipts,
            receipts_from_json(ffi_report),
            "FFI chunk receipts mismatch"
        );
        assert!(rust_duration > Duration::ZERO);
        assert!(js_duration > Duration::ZERO);
        assert!(ffi_duration > Duration::ZERO);
        let rust_ms = rust_duration.as_micros() as f64 / 1000.0;
        let js_ms = js_duration.as_micros() as f64 / 1000.0;
        let ffi_ms = ffi_duration.as_micros() as f64 / 1000.0;
        assert!(
            js_ms <= rust_ms * 10.0,
            "JS path is unexpectedly slow: {js_ms}ms vs Rust {rust_ms}ms"
        );
        assert!(
            ffi_ms <= rust_ms * 10.0,
            "FFI path is unexpectedly slow: {ffi_ms}ms vs Rust {rust_ms}ms"
        );
    }
}
