//! Independent strict profile generation and explicit compiled-profile inspection.

use super::*;
use iroha_core_zk::kagemusha_wallet_artifacts_v1::producer_inventory::{
    EncodedDirectoryOriginalsV1, EncodedTransportV1, OpeningMetricsV1, ProducerInventoryV1,
    TRANSPORT_MAX_BYTES_V1, WalletSourcesErrorV1,
};

struct InspectionSummary {
    routes: usize,
    programs: usize,
    peak_proving_bytes: u64,
}

/// Records `catalog_intake` and `snapshot_capture`; the body's own owner reports its stages.
fn with_encoded_snapshot<T>(
    root: &PrivateDirectory,
    inventory: &ProducerInventoryV1,
    opening: &mut OpeningMetricsV1,
    body: impl FnOnce(&mut dyn OriginalSourceV1) -> Result<T, WalletSourcesErrorV1>,
) -> io::Result<(T, Original)> {
    let transport_original = Original::open(
        root.path()
            .join("transport.json")
            .to_str()
            .ok_or_else(|| invalid("transport path"))?,
        TRANSPORT_MAX_BYTES_V1,
        None,
    )?;
    let transport = EncodedTransportV1::from_json(&transport_original.bytes)?;
    inspect::require_transport(inventory, &transport)?;
    let source = EncodedDirectoryOriginalsV1::open_existing(
        root.path().join("wallet-originals"),
        &transport,
    )?;
    opening.lap("catalog_intake");
    let result = source
        .with_snapshot(|snapshot| {
            opening.lap("snapshot_capture");
            let result = body(snapshot);
            opening.restart();
            result
        })
        .map_err(io::Error::other);
    // Metadata remains under its own retained original, also on body failure.
    transport_original.recheck()?;
    Ok((result?, transport_original))
}

fn finish_profile(
    inspection: Option<InspectionSummary>,
    started: std::time::Instant,
    recheck: impl FnOnce() -> io::Result<()>,
    output: &mut impl Write,
) -> io::Result<()> {
    // No terminal acceptance marker may precede a failed final custody check.
    recheck()?;
    let mode = if let Some(summary) = inspection {
        writeln!(
            output,
            "BUILTIN_SOURCE_ACCEPTED complete_routes={} complete_programs={} peak_proving_bytes={}",
            summary.routes, summary.programs, summary.peak_proving_bytes,
        )?;
        "compiled_inspection"
    } else {
        "strict_export"
    };
    writeln!(
        output,
        "BUILTIN_PROFILE_COMPLETE mode={mode} elapsed_ms={}",
        started.elapsed().as_millis(),
    )
}

#[derive(JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct BuiltinRequest {
    schema: String,
    carrier_directory: String,
    verifier_pack_name: String,
    originals_name: String,
    encoded: bool,
    scheme_id: String,
    manifest_digest: String,
    chain_id: String,
    network_id_hex: String,
    genesis_public_key: String,
    signed_genesis: OriginalInput,
    output_directory: String,
}

fn parse_request(bytes: &[u8]) -> io::Result<BuiltinRequest> {
    let request: BuiltinRequest = json::from_slice(bytes).map_err(io::Error::other)?;
    if request.schema != "iroha.kagemusha.builtin-source-profile.v1"
        || request.chain_id.is_empty()
        || request.chain_id.len() > 256
        || [&request.verifier_pack_name, &request.originals_name]
            .into_iter()
            .any(|name| {
                name.is_empty()
                    || name.len() > 128
                    || name == "."
                    || name == ".."
                    || !name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
            })
        || (request.encoded && request.originals_name != "wallet-originals")
    {
        return Err(invalid("unsupported built-in profile request"));
    }
    Ok(request)
}

/// Both modes authenticate the independent native genesis. Export always takes
/// the unconditional strict path and never looks up an existing registry entry.
///
/// # Errors
/// Returns request, genesis, source-qualification, custody, or output-publication errors.
pub fn run(path: &str, export: bool) -> io::Result<()> {
    let total = std::time::Instant::now();
    let mut opening = OpeningMetricsV1::start();
    let request_original = Original::open(path, REQUEST_MAX, None)?;
    let request = parse_request(&request_original.bytes)?;
    let root = PrivateDirectory::open_exact(&request.carrier_directory)?;
    let output = PrivateDirectory::open_exact(&request.output_directory)?;
    let open = |name: &str, maximum| {
        Original::open(
            root.path()
                .join(name)
                .to_str()
                .ok_or_else(|| invalid("carrier path"))?,
            maximum,
            None,
        )
    };
    let pack = open(
        &request.verifier_pack_name,
        iroha_core_zk::kagemusha_wallet_artifacts_v1::VERIFIER_PACK_MAX_BYTES_V1,
    )?;
    let catalog = open(
        "producer-inventory.norito",
        iroha_core_zk::kagemusha_wallet_artifacts_v1::producer_inventory::CATALOG_MAX_BYTES_V1,
    )?;
    let genesis = Original::open(
        &request.signed_genesis.path,
        GENESIS_MAX,
        Some(digest(&request.signed_genesis.sha256)?),
    )?;
    let native = native_finality(
        &request.chain_id,
        &request.network_id_hex,
        &request.genesis_public_key,
        &genesis.bytes,
    )?;
    opening.lap("selection");
    let pack_start = std::time::Instant::now();
    let installed = InstalledVerifierPackV1::load(
        &pack.bytes,
        InstallationV1 {
            scheme_id: digest(&request.scheme_id)?,
            manifest_digest: digest(&request.manifest_digest)?,
        },
    )
    .map_err(io::Error::other)?;
    println!(
        "BUILTIN_PROFILE_PHASE stage=pack_and_parameters elapsed_ms={}",
        pack_start.elapsed().as_millis()
    );
    opening.lap("verifier_pack");
    let inventory = installed
        .authenticate_producer_inventory(&catalog.bytes)
        .map_err(io::Error::other)?;
    let config = ReadConfig {
        maximum_bytes: PROVING_KEY_MAX_BYTES_V1,
        maximum_rows: 1 << 16,
        coset_cache: CosetCachePolicy::OnDemand,
        msm_budget: MemoryBudget::DEFAULT,
    };
    let graph_start = std::time::Instant::now();
    let (inspection, transport) = if export {
        // Independent registry generation keeps the original complete strict
        // file reader; it never consumes a compiled entry or admission snapshot.
        let (mut originals, transport): (Box<dyn OriginalSourceV1>, Option<Original>) =
            if request.encoded {
                inspect::open_sources(&root, &inventory, inspect::Encoding::Zstd)?
            } else {
                (
                    Box::new(DirectoryOriginalsV1::open_existing(
                        root.path().join(&request.originals_name),
                        PROVING_KEY_MAX_BYTES_V1,
                    )?),
                    None,
                )
            };
        eprintln!(
            "Strictly reconstructing every source and comparing every commitment before export."
        );
        let strict = inventory
            .qualify_strict_source_profile(&installed, &native, originals.as_mut(), config)
            .map_err(io::Error::other)?;
        let entry = strict
            .export_builtin_entry_rust(originals.as_mut(), config)
            .map_err(io::Error::other)?;
        request_original.recheck()?;
        pack.recheck()?;
        catalog.recheck()?;
        genesis.recheck()?;
        if let Some(transport) = &transport {
            transport.recheck()?;
        }
        root.revalidate()?;
        publish(&output, "builtin-profile-entry.rs", entry.as_bytes())?;
        (None, transport)
    } else {
        eprintln!(
            "Checking the complete exact built-in graph, all originals and independent native genesis."
        );
        let (wallet, transport) = if request.encoded {
            // Retain the exact authenticated DATA closure while the callback
            // consumes its opaque authenticated owner into the complete wallet.
            let expected = inventory.inventory().clone();
            let (wallet, transport) =
                with_encoded_snapshot(&root, &expected, &mut opening, |source| {
                    inventory.qualify_wallet_builtin(&installed, &native, source, config)
                })?;
            (wallet, Some(transport))
        } else {
            let mut originals = DirectoryOriginalsV1::open_existing(
                root.path().join(&request.originals_name),
                PROVING_KEY_MAX_BYTES_V1,
            )?;
            opening.lap("catalog_intake");
            let wallet = inventory
                .qualify_wallet_builtin(&installed, &native, &mut originals, config)
                .map_err(io::Error::other)?;
            opening.restart();
            (wallet, None)
        };
        opening.qualification(wallet.qualification_metrics());
        opening.lap("closing");
        let summary = InspectionSummary {
            routes: wallet.inventory().routes.len(),
            programs: wallet.inventory().operations.len(),
            peak_proving_bytes: wallet
                .peak_proving_memory_bytes()
                .map_err(io::Error::other)?,
        };
        (Some(summary), transport)
    };
    println!(
        "BUILTIN_PROFILE_PHASE stage=complete_graph elapsed_ms={}",
        graph_start.elapsed().as_millis()
    );
    finish_profile(
        inspection,
        total,
        || {
            request_original.recheck()?;
            pack.recheck()?;
            catalog.recheck()?;
            genesis.recheck()?;
            if let Some(transport) = transport {
                transport.recheck()?;
            }
            root.revalidate()
        },
        &mut io::stdout().lock(),
    )?;
    if !export {
        // Observation only, printed after every final custody check passed.
        opening.finish();
        println!("OPENING_METRICS {}", opening.to_json());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_core_zk::kagemusha_wallet_artifacts_v1::producer_inventory::{
        EncodedOriginalV1, OriginalV1,
    };

    fn encoded_fixture() -> (tempfile::TempDir, PrivateDirectory, ProducerInventoryV1) {
        let temp = tempfile::tempdir().unwrap();
        let root =
            PrivateDirectory::open_or_create(temp.path().canonicalize().unwrap().join("carrier"))
                .unwrap();
        let originals =
            PrivateDirectory::open_or_create(root.path().join("wallet-originals")).unwrap();
        let mut rows = Vec::new();
        let blobs = [b"descriptor".as_slice(), b"verifier", b"compact original"].map(|raw| {
            let stored = zstd::stream::encode_all(raw, 1).unwrap();
            let original = BlobV1::of(raw);
            publish(&originals, &hex::encode(original.sha256), &stored).unwrap();
            rows.push(EncodedOriginalV1 {
                original,
                stored: BlobV1::of(&stored),
            });
            original
        });
        rows.sort_by_key(|row| row.original.sha256);
        publish(
            &root,
            "transport.json",
            &EncodedTransportV1::new(rows).unwrap().to_json(),
        )
        .unwrap();
        // Structural DATA to exercise the reader boundary, never an authenticated
        // inventory or source-qualified wallet capability.
        let inventory = ProducerInventoryV1 {
            version: 1,
            native_profile: [1; 32],
            originals: vec![OriginalV1 {
                descriptor: blobs[0],
                verifying_key: blobs[1],
                proving_key: blobs[2],
            }],
            sigma: [0; 16],
            operations: Vec::new(),
            routes: Vec::new(),
            terminals: Vec::new(),
            omega: 0,
        };
        (temp, root, inventory)
    }

    #[test]
    fn compiled_inspection_snapshot_requires_complete_originals_before_body() {
        let (_temp, root, inventory) = encoded_fixture();
        let mut opening = OpeningMetricsV1::start();
        with_encoded_snapshot(&root, &inventory, &mut opening, |source| {
            let row = inventory.originals[0];
            for original in [row.descriptor, row.verifying_key, row.proving_key] {
                let mut bytes = Vec::new();
                source
                    .open(original.sha256)?
                    .read_to_end(&mut bytes)
                    .unwrap();
                assert_eq!(BlobV1::of(&bytes), original);
            }
            Ok(())
        })
        .unwrap();
        let names: Vec<_> = opening.phases().iter().map(|(name, _)| *name).collect();
        assert_eq!(names, ["catalog_intake", "snapshot_capture"]);
        let capture = opening.phase("snapshot_capture").unwrap().work;
        assert_eq!((capture.stored_files_opened, capture.zstd_decodes), (3, 3));
        let path = root
            .path()
            .join("wallet-originals")
            .join(hex::encode(inventory.originals[0].proving_key.sha256));
        std::fs::remove_file(path).unwrap();
        let mut entered = false;
        assert!(
            with_encoded_snapshot(&root, &inventory, &mut OpeningMetricsV1::start(), |_| {
                entered = true;
                Ok(())
            })
            .is_err()
        );
        assert!(!entered);
    }

    #[test]
    fn compiled_inspection_snapshot_closes_original_and_transport_custody() {
        for metadata in [false, true] {
            let (_temp, root, inventory) = encoded_fixture();
            let path = if metadata {
                root.path().join("transport.json")
            } else {
                root.path()
                    .join("wallet-originals")
                    .join(hex::encode(inventory.originals[0].descriptor.sha256))
            };
            let result =
                with_encoded_snapshot(&root, &inventory, &mut OpeningMetricsV1::start(), |_| {
                    std::fs::rename(&path, root.path().join("retained-old")).unwrap();
                    Ok("must not escape failed final custody")
                });
            assert!(result.is_err());
        }
    }

    #[test]
    fn final_custody_failure_cannot_print_a_terminal_acceptance_marker() {
        let mut output = Vec::new();
        let mut checked = false;
        let result = finish_profile(
            Some(InspectionSummary {
                routes: 52,
                programs: 32,
                peak_proving_bytes: 123,
            }),
            std::time::Instant::now(),
            || {
                checked = true;
                Err(invalid("changed final original"))
            },
            &mut output,
        );
        assert!(result.is_err());
        assert!(checked);
        assert!(output.is_empty());
    }

    #[test]
    fn terminal_markers_preserve_distinct_strict_and_compiled_modes() {
        for compiled in [false, true] {
            let mut output = Vec::new();
            let summary = compiled.then_some(InspectionSummary {
                routes: 52,
                programs: 32,
                peak_proving_bytes: 123,
            });
            finish_profile(summary, std::time::Instant::now(), || Ok(()), &mut output).unwrap();
            let output = String::from_utf8(output).unwrap();
            if compiled {
                assert!(output.starts_with("BUILTIN_SOURCE_ACCEPTED complete_routes=52 complete_programs=32 peak_proving_bytes=123\n"));
                assert!(
                    output
                        .contains("BUILTIN_PROFILE_COMPLETE mode=compiled_inspection elapsed_ms=")
                );
                assert_eq!(output.lines().count(), 2);
            } else {
                assert!(
                    output.starts_with("BUILTIN_PROFILE_COMPLETE mode=strict_export elapsed_ms=")
                );
                assert!(!output.contains("BUILTIN_SOURCE_ACCEPTED"));
                assert_eq!(output.lines().count(), 1);
            }
        }
    }

    fn request_text() -> String {
        r#"{"schema":"iroha.kagemusha.builtin-source-profile.v1","carrier_directory":"/private/test/carrier","verifier_pack_name":"verifier-pack.norito","originals_name":"wallet-originals","encoded":true,"scheme_id":"01","manifest_digest":"02","chain_id":"test-only","network_id_hex":"03","genesis_public_key":"test-only-public-key","signed_genesis":{"path":"/private/test/genesis","sha256":"04"},"output_directory":"/private/test/output"}"#.to_owned()
    }

    fn replace_string(text: &str, field: &str, original: &str, value: &str) -> String {
        text.replacen(
            &format!("\"{field}\":{}", json::to_string(original).unwrap()),
            &format!("\"{field}\":{}", json::to_string(value).unwrap()),
            1,
        )
    }

    #[test]
    fn closed_request_refuses_unknown_root_and_genesis_fields() {
        let text = request_text();
        assert!(parse_request(text.as_bytes()).is_ok());
        for changed in [
            text.replacen('{', "{\"source_digest\":\"caller-claim\",", 1),
            text.replacen(
                "\"signed_genesis\":{",
                "\"signed_genesis\":{\"trusted\":true,",
                1,
            ),
        ] {
            assert!(parse_request(changed.as_bytes()).is_err());
        }
    }

    #[test]
    fn carrier_names_are_bounded_single_safe_components() {
        // Raw mode permits a caller-selected original directory, but never a path.
        let text = request_text().replace("\"encoded\":true", "\"encoded\":false");
        for (field, original) in [
            ("verifier_pack_name", "verifier-pack.norito"),
            ("originals_name", "wallet-originals"),
        ] {
            for bad in [
                "",
                ".",
                "..",
                "../other",
                "/absolute",
                "a/b",
                "a\\b",
                "two words",
                "percent%2fpath",
                "non-ascii-日",
                "control\nname",
            ] {
                let changed = replace_string(&text, field, original, bad);
                assert!(
                    parse_request(changed.as_bytes()).is_err(),
                    "{field} accepted {bad:?}"
                );
            }
            let oversized = replace_string(&text, field, original, &"a".repeat(129));
            assert!(parse_request(oversized.as_bytes()).is_err());
            for good in ["a-Z_0.norito".to_owned(), "a".repeat(128)] {
                let changed = replace_string(&text, field, original, &good);
                assert!(parse_request(changed.as_bytes()).is_ok());
            }
        }
    }

    #[test]
    fn encoded_request_requires_exact_originals_directory() {
        let text = request_text();
        assert!(parse_request(text.as_bytes()).is_ok());
        for name in ["raw-originals", "Wallet-originals", "wallet-originals."] {
            let changed = replace_string(&text, "originals_name", "wallet-originals", name);
            assert!(parse_request(changed.as_bytes()).is_err());
            let raw = changed.replace("\"encoded\":true", "\"encoded\":false");
            assert!(parse_request(raw.as_bytes()).is_ok());
        }
    }

    #[test]
    fn request_requires_exact_schema_and_bounded_nonempty_chain() {
        let text = request_text();
        for schema in ["", "iroha.kagemusha.builtin-source-profile.v2"] {
            let changed = replace_string(
                &text,
                "schema",
                "iroha.kagemusha.builtin-source-profile.v1",
                schema,
            );
            assert!(parse_request(changed.as_bytes()).is_err());
        }
        for chain in [String::new(), "a".repeat(257), "日".repeat(86)] {
            let changed = replace_string(&text, "chain_id", "test-only", &chain);
            assert!(parse_request(changed.as_bytes()).is_err());
        }
        let bounded = replace_string(&text, "chain_id", "test-only", &"a".repeat(256));
        assert!(parse_request(bounded.as_bytes()).is_ok());
    }

    // One complete public-carrier opening as inspection runs it, with the encoded
    // admission snapshot, closing custody and every phase recorded. A source build
    // without a fresh compiled profile refuses the compiled graph exactly as phones
    // would; the strict graph then runs through the same snapshot so every stage is
    // measured. Observation DATA only: no custody root, key, enrollment or ledger action.
    fn public_carrier_opening(
        request: &BuiltinRequest,
        strict: bool,
    ) -> (String, OpeningMetricsV1) {
        let mut opening = OpeningMetricsV1::start();
        let root = PrivateDirectory::open_exact(&request.carrier_directory).unwrap();
        let read = |name: &str, maximum| {
            Original::open(root.path().join(name).to_str().unwrap(), maximum, None).unwrap()
        };
        let pack = read(
            &request.verifier_pack_name,
            iroha_core_zk::kagemusha_wallet_artifacts_v1::VERIFIER_PACK_MAX_BYTES_V1,
        );
        let catalog = read(
            "producer-inventory.norito",
            iroha_core_zk::kagemusha_wallet_artifacts_v1::producer_inventory::CATALOG_MAX_BYTES_V1,
        );
        let genesis = Original::open(
            &request.signed_genesis.path,
            GENESIS_MAX,
            Some(digest(&request.signed_genesis.sha256).unwrap()),
        )
        .unwrap();
        let native = native_finality(
            &request.chain_id,
            &request.network_id_hex,
            &request.genesis_public_key,
            &genesis.bytes,
        )
        .unwrap();
        opening.lap("selection");
        let installed = InstalledVerifierPackV1::load(
            &pack.bytes,
            InstallationV1 {
                scheme_id: digest(&request.scheme_id).unwrap(),
                manifest_digest: digest(&request.manifest_digest).unwrap(),
            },
        )
        .unwrap();
        opening.lap("verifier_pack");
        let inventory = installed
            .authenticate_producer_inventory(&catalog.bytes)
            .unwrap();
        let expected = inventory.inventory().clone();
        let config = ReadConfig {
            maximum_bytes: PROVING_KEY_MAX_BYTES_V1,
            maximum_rows: 1 << 16,
            coset_cache: CosetCachePolicy::OnDemand,
            msm_budget: MemoryBudget::DEFAULT,
        };
        let result = with_encoded_snapshot(&root, &expected, &mut opening, |source| {
            if strict {
                inventory.qualify_wallet(&installed, &native, source, config)
            } else {
                inventory.qualify_wallet_builtin(&installed, &native, source, config)
            }
        });
        let outcome = match result {
            Ok((wallet, transport)) => {
                opening.qualification(wallet.qualification_metrics());
                transport.recheck().unwrap();
                "accepted".to_owned()
            }
            Err(error) => error.to_string(),
        };
        opening.lap("closing");
        for original in [&pack, &catalog, &genesis] {
            original.recheck().unwrap();
        }
        root.revalidate().unwrap();
        opening.finish();
        (outcome, opening)
    }

    #[test]
    #[ignore = "complete public carrier opening; set KAGEMUSHA_OPENING_BASELINE_REQUEST and KAGEMUSHA_OPENING_BASELINE_OUTPUT"]
    fn public_carrier_opening_baseline() {
        let path = std::env::var("KAGEMUSHA_OPENING_BASELINE_REQUEST").unwrap();
        let output = std::env::var_os("KAGEMUSHA_OPENING_BASELINE_OUTPUT").unwrap();
        let request =
            parse_request(&Original::open(&path, REQUEST_MAX, None).unwrap().bytes).unwrap();
        assert!(request.encoded, "phones open the encoded carrier");
        let mut records = Vec::new();
        let mut accepted = false;
        for (mode, strict) in [("compiled", false), ("strict", true)] {
            let (outcome, opening) = public_carrier_opening(&request, strict);
            println!(
                "OPENING_BASELINE mode={mode} outcome={outcome:?} {}",
                opening.to_json()
            );
            accepted = outcome == "accepted";
            records.push(format!(
                "{{\"mode\":\"{mode}\",\"outcome\":{},\"metrics\":{}}}",
                json::to_string(&outcome).unwrap(),
                opening.to_json()
            ));
            if accepted {
                break;
            }
        }
        std::fs::write(output, format!("[{}]\n", records.join(","))).unwrap();
        assert!(accepted, "no complete graph qualified the public carrier");
    }
}
