fn print_usage() {
    eprintln!("xtask usage:");
    eprintln!("  cargo xtask soracloud-inrou-smoke portable");
    eprintln!("    Run the first-release hosted-HTTP Inrou PortableVm smoke harness.");
    eprintln!(
        "  cargo xtask openapi [--output <path>|--output-root <dir>] [--signature-envelope <path>|--unsigned-manifest] [--signing-payload <path>]"
    );
    eprintln!(
        "    Validate and emit Torii's compiled OpenAPI authority (the feature-pruned document Torii serves at /openapi.json). --output-root binds torii.json and manifest.json to one staging-safe canonical directory. Release signing is detached-only: emit the deterministic V2 payload with --unsigned-manifest --signing-payload, sign it with the external software signer, then attach --signature-envelope. Defaults to artifacts/openapi/torii.json"
    );
    eprintln!(
        "  cargo xtask da-threat-model-report [--out <path|->] [--seed <u64|0xhex>] [--config <path>]"
    );
    eprintln!(
        "    Run the DA PDP/PoTR simulator and emit a JSON summary for docs/automation. Defaults to artifacts/da/threat_model_report.json."
    );
    eprintln!(
        "  cargo xtask da-replication-audit --config <torii.toml> --manifest <path> [--manifest <path> ...] [--replication-order <path> ...] [--json-out <path|->] [--plan-out <path|->] [--allow-mismatch]"
    );
    eprintln!(
        "    Audit DA manifests and replication orders against the configured policy, emitting a JSON report and optional remediation plan."
    );
    eprintln!(
        "  cargo xtask da-commitment-reconcile --receipt <path> [--receipt <path> ...] --block <path> [--block <path> ...] [--json-out <path|->] [--allow-unexpected]"
    );
    eprintln!(
        "    Compare DA ingest receipts to DA commitment bundles (SignedBlockWire, .norito, or JSON) and fail on missing/mismatched tickets."
    );
    eprintln!(
        "  cargo xtask da-privilege-audit --config <torii.toml> [--extra-path <path> ...] [--json-out <path|->]"
    );
    eprintln!(
        "    Check DA ingest spool/cursor directories (and any extra paths) for missing/non-directory/world-writable permissions and emit an audit report."
    );
    eprintln!(
        "  cargo xtask da-proof-bench [--manifest <path>] [--payload <path>] [--payload-bytes <n>] [--sample-count <n>] [--sample-seed <u64|0xhex>] [--budget-ms <u64>] [--iterations <n>] [--json-out <path|->] [--markdown-out <path|->]"
    );
    eprintln!(
        "    Measure PoR verification time against the Halo2 verifier budget using the provided manifest/payload (defaults to fixtures/da/reconstruct/rs_parity_v1). Fails if verification exceeds the budget."
    );
    eprintln!(
        "  cargo xtask kagami-profiles --xor-allocations-dir <DIR> [--profile <iroha3-dev|iroha3-nexus>] [--out <dir>] [--kagami <path>] [--nexus-xor-asset-definition-id <BASE58>]"
    );
    eprintln!(
        "    Rebuild the canned Kagami profile bundles (genesis + PoPs + snippets) under defaults/kagami for Iroha 3 smoke tests; Nexus regeneration requires an explicit canonical XOR asset id."
    );
    eprintln!("  cargo xtask address-vectors [--out <path>] [--stdout] [--verify]");
    eprintln!(
        "    Emit or verify the ADDR-2 I105/multisig fixture. Defaults to fixtures/account/address_vectors.json"
    );
    eprintln!(
        "  cargo xtask zk-dev-vote-fixture [--out <path>] [--verify] [--print-hashes] [--summary-json <path|->] [--attestation <path|->]"
    );
    eprintln!(
        "    Rebuild or verify development-only membership fixtures (requires --features dev-vote-fixture). Defaults to fixtures/zk/dev_vote_membership"
    );
    eprintln!("    Run once without --verify to seed fixtures before using --verify.");
    eprintln!("    Use --summary-json - to emit JSON on stdout or provide a path to write a file.");
    eprintln!(
        "    Use --attestation - to emit artifact hashes on stdout or provide a path to write a file."
    );
    eprintln!("    Proof envelope hashes are deterministic; mismatches indicate drift.");
    eprintln!("  cargo xtask soranet-fixtures [--out <path>] [--verify]");
    eprintln!(
        "    Generate SoraNet capability negotiation and downgrade telemetry fixtures. Defaults to tests/interop/soranet/capabilities"
    );
    eprintln!(
        "  cargo xtask soranet-chaos-kit [--out <dir>] [--pop <label>] [--gateway <host>] [--resolver <host>] [--quarter <label>] [--now <unix-secs>]"
    );
    eprintln!(
        "    Generate the SNNet-15F1 chaos GameDay kit (plan, scripts, shared log) under artifacts/soranet/chaos_game_day/<date>."
    );
    eprintln!("  cargo xtask soranet-chaos-report --log <path> [--out <path|->]");
    eprintln!(
        "    Summarise a chaos GameDay log (NDJSON) into JSON detection/recovery timings; defaults to stdout."
    );
    eprintln!(
        "  cargo xtask soranet-pop-bundle --input <path> [--roa <path>] [--output-dir <path>] [--edns-resolver <addr>] [--edns-tool <bin>] [--skip-edns] [--skip-ds] [--image-tag <tag>]"
    );
    eprintln!(
        "    Build a PoP provisioning bundle (SN15-M0-2): FRR + resolver templates, optional EDNS/DS evidence, PXE/env/secret/checklist/CI stubs, sign-off bundle, and a checksum manifest. Defaults to artifacts/soranet_pop/bundle."
    );
    eprintln!(
        "  cargo xtask soranet-popctl --input <path> [--roa <path>] [--output-dir <path>] [--edns-resolver <addr>] [--edns-tool <bin>] [--skip-edns] [--skip-ds] [--image-tag <tag>]"
    );
    eprintln!(
        "    Alias for soranet-pop-bundle with the popctl naming used in SN15-M0-2 docs; emits the same bundle with the signoff/CI assets staged for attestation."
    );
    eprintln!(
        "  cargo xtask soranet-pop-template --input <path> [--output <path>] [--resolver-config <path>] [--edns-out <path>] [--edns-resolver <addr>] [--edns-tool <bin>] [--ds-out <path>]"
    );
    eprintln!(
        "    Render an FRR config for a SoraNet PoP (SNNet-15A2) and optionally emit resolver templates plus EDNS/DS evidence. Defaults to artifacts/soranet_pop/frr.conf when --output is omitted."
    );
    eprintln!(
        "  cargo xtask soranet-pop-validate --input <path> [--roa <path>] [--json-out <path|->]"
    );
    eprintln!(
        "    Validate a PoP descriptor (SNNet-15A1/A2) with optional ROA bundle, surfacing BFD/RPKI defaults and ROA gaps. Defaults to stdout when --json-out is omitted."
    );
    eprintln!(
        "  cargo xtask soranet-pop-policy-report --input <path> [--roa <path>] [--output-dir <path>] [--grafana-out <path>] [--alert-rules-out <path>] [--json-out <path>]"
    );
    eprintln!(
        "    Generate the SN15-M0-3 BGP policy harness: Prometheus alert rules, Grafana dashboard, and a JSON report with route-health baselines. Defaults to artifacts/soranet_pop/policy."
    );
    eprintln!(
        "  cargo xtask soranet-pop-plan --input <path> [--roa <path>] [--frr-out <path>] [--json-out <path|->]"
    );
    eprintln!(
        "    Render FRR config and emit a validation JSON report in one run. Defaults: artifacts/soranet_pop/frr.conf for config, stdout for JSON."
    );
    eprintln!("  cargo xtask soranet-gateway-m0 [--output-dir <path>] [--edge-name <name>]");
    eprintln!(
        "    Emit the SNNet-15M0 gateway baseline pack (H3 edge config, trustless verifier skeleton, WAF/rate policy) with a JSON summary. Defaults to configs/soranet/gateway_m0."
    );
    eprintln!("  cargo xtask soranet-gateway-m1 [--config <path>] [--output-dir <path>]");
    eprintln!(
        "    Build the SNNet-15M1 alpha bundle (PoP provisioning, gateway baselines, ops packs, billing dry-run) into a single evidence root. Defaults to configs/soranet/gateway_m1/alpha_config.json and artifacts/soranet/gateway_m1/alpha."
    );
    eprintln!("  cargo xtask soranet-gateway-m2 [--config <path>] [--output-dir <path>]");
    eprintln!(
        "    Build the SNNet-15M2 beta bundle (DoQ/ODoH preview configs, trustless verifier wiring, compliance + hardening summaries, prepaid billing). Qualify PQ separately with the strict soranet-gateway-pq command. Defaults to configs/soranet/gateway_m2/beta_config.json and artifacts/soranet/gateway_m2/beta."
    );
    eprintln!(
        "  cargo xtask soranet-gateway-m3 --m2-summary <path> --autoscale-plan <path> --worker-pack <path> [--out <path>] [--sla-target <label>]"
    );
    eprintln!(
        "    Emit the SNNet-15M3 GA readiness bundle by hashing autoscale/worker artefacts and linking the M2 summary; outputs JSON + Markdown evidence."
    );
    eprintln!("  cargo xtask soranet-gateway-ops-m0 [--output-dir <path>] [--pop <name>]");
    eprintln!(
        "    Emit the SN15-M0 ops pack (OTEL pipeline, alerts, GameDay, GAR/security outlines) with a JSON summary. Defaults to configs/soranet/gateway_m0/observability."
    );
    eprintln!(
        "  cargo xtask soranet-gateway-pq --srcv2 <path> --issuer-ed25519-hex <hex> --issuer-mldsa65-hex <hex> --tls-bundle <dir> --trustless-config <path> --at-unix <unix-seconds> [--pop <name>] [--out <dir>]"
    );
    eprintln!(
        "    Generate the SNNet-15PQ readiness bundle (time-bound SRCv2 dual-signature validation, TLS/ECH evidence, and trustless verifier config) under artifacts/soranet/gateway_pq unless overridden."
    );
    eprintln!("  cargo xtask soranet-bug-bounty --config <path> [--output-dir <path>]");
    eprintln!(
        "    Generate the SNNet-15H1 pen-test and bug bounty kit (overview, triage checklist, remediation template, summary). Defaults to artifacts/soranet/gateway/bug_bounty."
    );
    eprintln!(
        "  cargo xtask soranet-gateway-ops-m1 [--output-dir <path>] [--pops <a,b,c>] [--pop <name>...]"
    );
    eprintln!(
        "    Emit the federated SNNet-15F ops pack for multiple PoPs (per-pop bundles, federated OTEL collector, and GameDay rotation). Defaults to configs/soranet/gateway_m1."
    );
    eprintln!(
        "  cargo xtask soranet-gateway-chaos [--config <path>] [--out <dir>] [--pop <name>] [--scenario <id|all>] [--execute] [--note <text>]"
    );
    eprintln!(
        "    Run or dry-run SNNet-15F1 chaos drills from the scenario pack; defaults to artifacts/soranet/gateway_chaos and the ops-pack scenarios."
    );
    eprintln!(
        "  cargo xtask soranet-gateway-hardening [--sbom <path>] [--vuln-report <path>] [--signing-policy <path>] [--sandbox-profile <path>] [--data-retention-days <u32>] [--log-retention-days <u32>] [--out <dir>]"
    );
    eprintln!(
        "    Generate the SNNet-15H hardening summary (SBOM/vulnerability/signing-policy/sandbox evidence + retention defaults) with JSON + Markdown outputs. Defaults to artifacts/soranet/gateway_hardening."
    );
    eprintln!(
        "  cargo xtask soranet-gar-controller [--config <path>] [--output-dir <path>] [--markdown-out <path>] [--now <unix-secs>]"
    );
    eprintln!(
        "    Build the SNNet-15G GAR controller bundle (NATS event spool, per-pop receipts, summary, Markdown report). Defaults to configs/soranet/gateway_m0/gar_controller.sample.json and artifacts/soranet/gateway/gar_controller."
    );
    eprintln!(
        "  cargo xtask soranet-gar-export [--pop <name>] [--receipts-dir <path>] [--acks-dir <path>] [--json-out <path|->] [--markdown-out <path>] [--now <unix-secs>]"
    );
    eprintln!(
        "    Bundle GAR enforcement receipts and ACK files into a JSON summary (and optional Markdown). Defaults to artifacts/soranet/gateway/<pop>/gar_receipts*, using stdout when no pop/paths are supplied."
    );
    eprintln!(
        "  cargo xtask soranet-gateway-billing [--usage <path>] [--catalog <path>] [--guardrails <path>] [--output-dir <path>] [--payer <account>] [--treasury <account>] [--asset <definition>] [--allow-hard-cap]"
    );
    eprintln!(
        "    Rate Gateway usage against the SN15-M0 catalog, exporting JSON/CSV/Parquet invoices plus ledger projection and reconciliation report. Defaults use configs/soranet/gateway_m0/billing_usage_sample.json and configs/soranet/gateway_m0/meter_catalog.json."
    );
    eprintln!("  cargo xtask sorafs-gateway-fixtures [--out <dir>] [--verify]");
    eprintln!(
        "    Generate the canonical SoraFS gateway conformance fixtures. Defaults to fixtures/sorafs_gateway/<version>"
    );
    eprintln!("  cargo xtask sorafs-admission-fixtures [--out <dir>]");
    eprintln!(
        "    Regenerate the provider admission proposal/envelope fixtures. Defaults to fixtures/sorafs_manifest/provider_admission"
    );
    eprintln!(
        "  cargo xtask soradns-hosts --name <fqdn> [--name <fqdn> ...] [--pretty-suffix <suffix>] [--json-out <path|->] [--verify-host-patterns <path> ...]"
    );
    eprintln!(
        "    Derive canonical and pretty gateway hosts for SoraDNS names. Use --json-out to write structured output and --verify-host-patterns to compare derived hosts against GAR host_patterns JSON."
    );
    eprintln!(
        "  cargo xtask soradns-binding-template --manifest <path> --alias <alias> --hostname <host> [--route-label <label>] [--proof-status <status>] [--csp-template <string>] [--permissions-template <string>] [--hsts-template <string>] [--json-out <path|->] [--headers-out <path>] [--generated-at <RFC3339>]"
    );
    eprintln!(
        "    Generate a portal.gateway.binding.json replacement plus the matching headers.txt block so DG-3 tickets can diff alias/CID/route metadata without running the Node helper."
    );
    eprintln!(
        "  cargo xtask soradns-gar-template --name <fqdn> [--pretty-suffix <suffix>] [--manifest <path> | --manifest-cid <cid>] [--manifest-digest <hex>] [--valid-from <secs>] [--valid-until <secs>] [--csp-template <string>] [--hsts-template <string>] [--permissions-template <string>] [--telemetry-label <label> ...] [--json-out <path|->]"
    );
    eprintln!(
        "    Scaffold a Gateway Authorization Record payload with canonical host patterns, default CSP/HSTS templates, and optional telemetry labels. Use --json-out - to emit the JSON on stdout."
    );
    eprintln!(
        "  cargo xtask soradns-acme-plan --name <fqdn> [--name <fqdn> ...] [--pretty-suffix <suffix>] [--directory-url <url>] [--no-pretty] [--no-canonical-wildcard] [--generated-at <RFC3339>] [--json-out <path|->]"
    );
    eprintln!(
        "  cargo xtask soradns-cache-plan --name <fqdn> [--name <fqdn> ...] [--pretty-suffix <suffix>] [--path <path> ...] [--http-method <verb>] [--no-pretty] [--auth-header <name>] [--auth-env <env>] [--generated-at <RFC3339>] [--json-out <path|->]"
    );
    eprintln!(
        "    Emit deterministic cache invalidation plans (hosts + paths + auth hints) so DG-3 change packets can include purge flows alongside GAR/binding templates."
    );
    eprintln!(
        "  cargo xtask soradns-route-plan --name <fqdn> [--name <fqdn> ...] [--pretty-suffix <suffix>] [--no-pretty] [--generated-at <RFC3339>] [--json-out <path|->]"
    );
    eprintln!(
        "    Produce promotion + rollback checklists per alias, including canonical/pretty hosts and staging notes, so DG-3 route changes ship with preflight + revert evidence."
    );
    eprintln!(
        "    Render the wildcard + pretty-host SAN plan with recommended ACME challenges and DNS-01 labels so TLS automation and GAR reviewers share the same evidence bundle."
    );
    eprintln!(
        "  cargo xtask soradns-verify-gar --gar <path> --name <fqdn> [--pretty-suffix <suffix>] [--manifest-cid <cid>] [--manifest-digest <hex>] [--telemetry-label <label> ...] [--json-out <path|->]"
    );
    eprintln!(
        "    Validate a GAR payload against the deterministic host policy before signing or attaching it to DG-3 tickets. Confirms canonical/pretty hosts, manifest metadata, and required telemetry labels."
    );
    eprintln!(
        "  cargo xtask soradns-verify-binding --binding <portal.gateway.binding.json> [--alias <alias>] [--content-cid <cid>] [--hostname <host>] [--proof-status <status>] [--manifest-json <path>]"
    );
    eprintln!(
        "    Validate gateway binding artefacts before attaching them to DG-3 change tickets. Confirms Sora-Name/Proof headers, route metadata, and proof payloads match the expected alias/content CID."
    );
    eprintln!(
        "  cargo xtask sorafs-adoption-check [--scoreboard <path>] [--summary <path>] [--min-providers <count>] [--allow-zero-weight] [--allow-single-source] [--adoption-override-id <id>] [--allow-implicit-metadata] [--require-direct-only] [--require-telemetry] [--require-telemetry-region] [--report <path>]"
    );
    eprintln!(
        "    Validate multi-source adoption evidence by inspecting persisted orchestrator scoreboards and summaries."
    );
    eprintln!(
        "    Provide --report to persist the aggregated JSON summary alongside other release artefacts."
    );
    eprintln!(
        "  cargo xtask sorafs-scoreboard-diff --previous <path> --current <path> [--threshold-percent <float>] [--report <path>]"
    );
    eprintln!(
        "    Compare eligible provider weights between scoreboards; highlights deltas and flags entries exceeding the configured threshold."
    );
    eprintln!(
        "  cargo xtask compute slo-report [--manifest <path>] [--json-out <path>] [--markdown-out <path|->] [--samples <n>]"
    );
    eprintln!(
        "    Generate a deterministic compute SLO report (JSON + optional Markdown) using the built-in harness; defaults to fixtures/compute/manifest_compute_payments.json and artifacts/compute/compute_slo_report.{{json,md}}."
    );
    eprintln!("  cargo xtask compute fixtures [--output <dir>]");
    eprintln!(
        "    Emit cross-SDK compute fixtures (call, receipt, rejection catalog) into fixtures/compute/sdk_parity or the provided directory."
    );
    eprintln!(
        "  cargo xtask taikai-anchor-bundle [--spool <dir>] [--copy-dir <dir>] [--receipt-public-key <multihash>] [--signing-key <path>] [--out <path|->]"
    );
    eprintln!(
        "    Scan the Taikai spool for anchor artefacts, verify content-bound receipts when an Ed25519 anchor key is supplied, optionally copy files into a bundle dir, and sign the report. Receipts are never reported as delivered without verification."
    );
    eprintln!(
        "  cargo xtask taikai-rpt-verify --envelope <path> --gar <path> --cek-receipt <path> --bundle <path> [--json-out <path|->]"
    );
    eprintln!(
        "    Decode a replication proof token (.to or JSON) and verify every referenced GAR, CEK receipt, and bundle digest. Use --json-out - to emit the structured report on stdout."
    );
    eprintln!(
        "  cargo xtask sorafs-burn-in-check --log <telemetry.log> [--log <telemetry.log>] [--window-days <days>] [--min-pq-ratio <ratio>] [--max-brownout-ratio <ratio>] [--max-no-provider-errors <count>] [--min-fetches <count>] [--out <path>]"
    );
    eprintln!(
        "    Parse telemetry::sorafs.fetch.* logs, enforce the burn-in SLO (window + PQ/brownout ratios + failure limits), and emit a JSON summary (stdout by default)."
    );
    eprintln!(
        "  cargo xtask sorafs-reserve-matrix [--capacity <GiB>]... [--storage-class <hot|warm|cold>]... [--tier <tier-a|tier-b|tier-c>]... [--duration <monthly|quarterly|annual>] [--policy-json <path>] [--policy-norito <path>] [--reserve-balance <XOR>] [--out <path|->]"
    );
    eprintln!(
        "    Generate a rent/reserve quote matrix for dashboards and economics tooling. Defaults to stdout when --out is omitted."
    );
    eprintln!("  cargo xtask sorafs-pin-fixtures [--out <path>]");
    eprintln!(
        "    Rebuild the pin registry snapshot fixture (manifests, aliases, replication orders). Defaults to crates/iroha_core/tests/fixtures/sorafs_pin_registry/snapshot.json"
    );
    eprintln!(
        "  cargo xtask nexus-connect-fixture --print | (--write|--check) --output-root <absolute-directory>"
    );
    eprintln!(
        "    Emit the exact native JSON with --print; file write mode still refuses Git checkouts and requires an external staging root."
    );
    eprintln!("  cargo xtask nexus-lane-maintenance --config <path>");
    eprintln!(
        "    Emit a read-only JSON inventory to stdout; declared lanes and physical canonical/instance paths do not prove active or retired ownership."
    );
    eprintln!(
        "  cargo xtask nexus-lane-audit --status <status.json> [--json-out <path>] [--parquet-out <path>] [--markdown-out <path>] [--captured-at <iso8601>] [--lane-compliance <path>]"
    );
    eprintln!(
        "    Export the current lane telemetry snapshot (JSON + Parquet + Markdown) for regulators. Defaults to artifacts/nexus_lane_audit.{{json,parquet,md}}; pass --lane-compliance to embed policy/review evidence."
    );
    eprintln!("  cargo xtask space-directory encode --json <path> [--out <path>]");
    eprintln!(
        "    Encode an AssetPermissionManifest JSON file into Norito bytes (.to). Defaults to replacing the input extension with .to"
    );
    eprintln!(
        "  cargo xtask sorafs-fetch-fixture --signatures <path|url> [--manifest <path|url>] [--out <dir>] [--profile <handle>] [--allow-unsigned]"
    );
    eprintln!(
        "    Download the Parliament-approved chunker manifest + signature envelope, verify digests/signatures, and write them to fixtures/sorafs_chunker."
    );
    eprintln!(
        "  cargo xtask sorafs-gateway-attest --signing-key <path> --signer-account <account> [--gateway <url>] [--out <dir>]"
    );
    eprintln!(
        "    Run the SoraFS gateway conformance harness, then write the JSON report, attestation envelope, and summary to artifacts/sorafs_gateway_attest unless --out is provided."
    );
    eprintln!("  cargo xtask sorafs-gateway-attest --verify <attestation.to>");
    eprintln!(
        "    Verify a SoraFS gateway conformance attestation envelope by recomputing the embedded report hash and checking the signer signature."
    );
    eprintln!(
        "  cargo xtask sorafs-gateway-probe --gateway <url>|--headers-file <path> --gar <path> --gar-key kid=hex [options]"
    );
    eprintln!(
        "    Fetch gateway headers (or parse a captured dump) and verify Sora-* headers, GAR manifest metadata, CSP/HSTS templates, cache TTLs, and TLS state."
    );
    eprintln!(
        "    Use --report-json <path|-> to capture a machine-readable summary for paging/drill automation."
    );
    eprintln!(
        "  cargo xtask sorafs-gateway tls renew --host <hostname>... --out <dir> [--account-email <email>] [--directory-url <url>] [--dns-provider-id <id>] [--force]"
    );
    eprintln!(
        "    Generate a TLS bundle using the self-signed ACME client and write fullchain.pem, privkey.pem, and ech.json to the target directory."
    );
    eprintln!(
        "  cargo xtask sorafs-gateway tls revoke --out <dir> [--archive-dir <dir>] [--reason <text>] [--force]"
    );
    eprintln!(
        "    Archive the current TLS bundle into a timestamped backup to simulate revocation on hosts without production ACME wiring."
    );
    eprintln!(
        "  cargo xtask sorafs-gateway key rotate --kind token-signing --out <path> [--public-out <path>] [--force]"
    );
    eprintln!(
        "    Rotate the stream-token signing key, writing the private key to disk and printing the new public key fingerprint."
    );
    eprintln!(
        "  cargo xtask soranet-privacy-report --input <ndjson> [--input <ndjson> ...] [--bucket-secs <n>] [--min-contributors <n>] [--json-out <path|->] [--max-buckets <n>] [--max-suppression-ratio <0-1>]"
    );
    eprintln!(
        "    Summarise SNNet-8 privacy buckets from NDJSON/Prio share exports, highlight suppression reasons, optionally emit machine-readable reports, and fail fast when suppression exceeds the provided ratio budget."
    );
    eprintln!(
        "  cargo xtask soranet-constant-rate-profile [--profile core|home] [--format table|json|markdown] [--tick-table] [--tick-values <v1,v2,...>]"
    );
    eprintln!(
        "    Print the SNNet-17B constant-rate presets (core/home) and optional tick→bandwidth tables so relay operators and SDK tooling can apply consistent lane budgets."
    );
    eprintln!("  cargo xtask norito-rpc-fixtures --output-root <absent-absolute-external-dir>");
    eprintln!("{NORITO_RPC_FIXTURES_USAGE_DESCRIPTION}");
    eprintln!(
        "  cargo xtask norito-rpc-fixtures --local-integration --output-root <checkout>/target/norito-rpc-local/<absent-name>"
    );
    eprintln!(
        "    Checkout-local test publication only; target/norito-rpc-local must already be an owner-private mode-0700 directory."
    );
    eprintln!("  cargo xtask norito-rpc-verify [--json-out <path|->]");
    eprintln!("{NORITO_RPC_VERIFY_USAGE_DESCRIPTION}");
    eprintln!("  cargo xtask soranet-testnet-kit [--out <dir>]");
    eprintln!(
        "    Materialise the SoraNet testnet operator kit. Defaults to fixtures/documentation/soranet_testnet_operator_kit"
    );
    eprintln!("  cargo xtask soranet-testnet-metrics --input <metrics.json> [--out <path|->]");
    eprintln!(
        "    Evaluate SNNet-10 success metrics from an aggregated snapshot. Emits a pass/fail report (use --out - for stdout)."
    );
    eprintln!(
        "  cargo xtask soranet-testnet-feed --promotion <label> --window-start <YYYY-MM-DD> --window-end <YYYY-MM-DD> --metrics-report <path> [--relay <id>]... [--relays-file <path>] [--drill-log <path>] [--stage-report <path>] [--attachment label=path]... [--out <path|->]"
    );
    eprintln!(
        "    Aggregate metrics, relay roster, and artefact hashes into a deterministic JSON feed for SNNet-10 stage-gate reviews."
    );
    eprintln!(
        "  cargo xtask soranet-testnet-drill-bundle --log <path> --signing-key <path> [--promotion <label>] [--window-start <YYYY-MM-DD>] [--window-end <YYYY-MM-DD>] [--attachment label=path]... [--out <path|->]"
    );
    eprintln!(
        "    Sign SNNet-10 drill logs plus attachments and emit a deterministic bundle for governance packets and feed ingestion."
    );
    eprintln!(
        "  cargo xtask fastpq-bench-manifest --bench <label=path>... [--require-rows <count>] [--max-operation-ms op=value]... [--min-operation-speedup op=value]... [--matrix <path>] [--signing-key <path>] [--out <path>]"
    );
    eprintln!(
        "    Validate Metal/CUDA benchmark bundles, enforce latency/speedup thresholds, and emit a (optionally signed) manifest with BLAKE3/SHA-256 digests for release gating."
    );
    eprintln!(
        "  cargo xtask fastpq-stage-profile [--rows <count>] [--warmups <count>] [--iterations <count>] [--out-dir <path>] [--trace] [--trace-dir <path>] [--trace-template <template>] [--trace-seconds <seconds>] [--stage <fft|ifft|lde|digest384_trace_columns|digest384_merkle_pairs|bn254_poseidon_words>] [--debug] [--no-gpu-probe]"
    );
    eprintln!(
        "    Run the Metal bench across selected stages, capture optional traces, and emit per-stage summaries for local profiling."
    );
    eprintln!(
        "  cargo xtask fastpq-cuda-suite [--rows <count>] [--warmups <count>] [--iterations <count>] [--columns <count>] [--operation <fft|ifft|lde|digest384_trace_columns|digest384_merkle_pairs|bn254_poseidon_words|all>] [--output <path>] [--raw-output <path>] [--row-usage <path>] [--label key=value]... [--device <label>] [--notes <text>] [--require-gpu] [--sign-output] [--gpg-key <id>] [--accel-instance <label>] [--accel-state-json <path>] [--accel-state-prom <path>] [--no-wrap] [--dry-run]"
    );
    eprintln!(
        "    Drive the CUDA bench harness, optionally wrap/sign the bundle with row-usage/acceleration-state metadata, and record a plan JSON so GPU runners produce reproducible Stage7 evidence. Filtered runs only enforce wrap thresholds for the selected operation."
    );
    eprintln!(
        "  cargo xtask soranet-rollout-plan --regions <r1,r2,...> --start <RFC3339> [--window <dur>] [--spacing <dur>] [--client-offset <dur>] [--phase <label>] [--environment <name>] [--out <path>] [--markdown-out <path>]"
    );
    eprintln!(
        "    Generate SNNet-16 rollout scheduling artefacts (JSON/Markdown). Duration arguments accept s/m/h/d suffixes."
    );
    eprintln!(
        "  cargo xtask soranet-rollout-capture --log <path> --key <ed25519_hex> [--artifact kind=...,path=...]... [--out <dir>] [--phase <label>] [--environment <name>] [--label <tag>] [--note <text>]"
    );
    eprintln!(
        "    Copy rollout drill artefacts, compute BLAKE3 digests, and emit a signed metadata package for rollback rehearsals."
    );
    eprintln!(
        "  cargo xtask sm-wycheproof-sync (--input <path>|--input-url <url>) [--output <path>] [--generator-version <tag>] [--minify|--pretty]"
    );
    eprintln!(
        "    Sanitize an upstream Wycheproof SM2 JSON suite and write the trimmed fixture to crates/iroha_crypto/tests/fixtures/wycheproof_sm2.json."
    );
    eprintln!(
        "  cargo xtask sm-operator-snippet [--distid <id>] [--seed-hex <hex>] [--json-out <path|->] [--snippet-out <path|->]"
    );
    eprintln!(
        "    Generate SM2 operator artifacts (`sm2-key.json`, `client-sm2.toml`) without relying on jq (use `-` to stream to stdout)."
    );
    eprintln!(
        "  cargo xtask codec rans-tables [--seed <u64>] [--bundle-width <2-4>] [--output <path>] [--format json|toml|csv] [--signing-key <path>] [--verify [path]]"
    );
    eprintln!(
        "    Generate deterministic rANS initialisation tables for NSC-55. Defaults to artifacts/nsc/rans_tables.(json|toml). Use --bundle-width to pick the maximum bundle size; narrower tables are derived deterministically."
    );
    eprintln!("  cargo xtask verify-tables [--tables <path> ...]");
    eprintln!(
        "    Verify SignedRansTablesV1 artefacts by re-running deterministic generation and signature checks. Defaults to codec/rans/tables/rans_seed0.toml."
    );
    eprintln!(
        "    Use --signing-key to attach an Ed25519 signature and --verify to validate existing artefacts against the current generator."
    );
    eprintln!(
        "  cargo xtask streaming-bundle-check --config <path> [--tables <path>] [--json-out <path|->]"
    );
    eprintln!(
        "    Inspect the streaming codec config, load the SignedRansTablesV1 artefact, and emit checksum metadata in JSON form for rollout/runbook evidence."
    );
    eprintln!(
        "  cargo xtask streaming-entropy-bench [--frames <count>] [--segments <count>] [--width <n>] [--quantizer <qp>]... [--target-bitrate-mbps <mbps>]... [--tiny-clip-preset] [--psnr-mode y|yuv] [--json-out <path|->]"
    );
    eprintln!(
        "    Benchmark baseline vs bundled (when enabled) entropy encoding/decoding and emit chunk/latency metrics as JSON for CI dashboards. PSNR supports luma-only (`--psnr-mode y`) and full YUV (`--psnr-mode yuv`). Pass `--quantizer` multiple times to sweep QPs, `--target-bitrate-mbps` to record ladder selections, and `--tiny-clip-preset` for 16–32 px clips."
    );
    eprintln!(
        "  cargo xtask streaming-decode --bundle <path> --y4m-out <path> [--psnr-ref <y4m>] [--psnr-mode y|yuv] [--json-out <path|->]"
    );
    eprintln!(
        "    Decode serialized Norito streaming bundles into Y4M clips for RD tooling; optionally compute PSNR/PSNR-YUV against a reference Y4M."
    );
    eprintln!(
        "  cargo xtask stage1-bench [--size <bytes|Nk|Nm>]... [--iterations <n>] [--json-out <path>] [--markdown-out <path>] [--allow-overwrite]"
    );
    eprintln!(
        "    Benchmark Norito JSON stage-1 (scalar vs accelerated) across sizes, emit JSON/Markdown summaries, and report a recommended acceleration threshold."
    );
    eprintln!(
        "  cargo xtask poseidon-cuda-bench [--batch-size <n>] [--iterations <n>] [--json-out <path>] [--markdown-out <path>] [--allow-overwrite]"
    );
    eprintln!(
        "    Run Poseidon2/6 parity + throughput for scalar vs CUDA backends, emitting JSON/Markdown under benchmarks/poseidon with CUDA/Metal runtime health."
    );
    eprintln!(
        "  cargo xtask streaming-context-remap --input <bundled_telemetry.json> [--top <n>] [--json-out <path|->]"
    );
    eprintln!(
        "    Analyse bundled telemetry context frequencies, emit a deterministic remap table for the top-N contexts, and record the dominant symbol mix for pruning/refresh runbooks."
    );
    eprintln!(
        "  cargo xtask ministry-transparency ingest --quarter <YYYY-Q> --ledger <path> --appeals <path> --denylist <path> --treasury <path> [--volunteer <path>] [--red-team-report <path> ...] --output <path>"
    );
    eprintln!(
        "    Run the Ministry transparency ingest job to build the quarterly snapshot described in specs/ministry/transparency_plan.md."
    );
    eprintln!(
        "  cargo xtask ministry-transparency build --ingest <path> --metrics-out <path> --manifest-out <path> [--note <text>]"
    );
    eprintln!(
        "    Produce dashboard-ready metrics and a signed manifest from an ingest snapshot so MINFO-8 transparency packets are deterministic."
    );
    eprintln!(
        "  cargo xtask ministry-transparency sanitize --ingest <path> --output <path> --report <path> [--epsilon-counts <f64> --epsilon-accuracy <f64> --delta <f64> --suppress-threshold <u64> --min-accuracy-samples <u64> --seed <u64>]"
    );
    eprintln!(
        "    Apply the DP sanitizer from specs/ministry/transparency_plan.md to an ingest snapshot, emitting sanitized metrics and an audit report."
    );
    eprintln!(
        "  cargo xtask ministry-transparency volunteer-validate --input <path> [--input <path> ...] [--json-output <path>]"
    );
    eprintln!(
        "    Validate volunteer brief payloads against specs/ministry/volunteer_brief_template.md before publishing."
    );
    eprintln!(
        "  cargo xtask ministry-agenda validate --proposal <path> [--registry <path>] [--allow-registry-conflicts]"
    );
    eprintln!(
        "    Validate Agenda Council proposal payloads (specs/ministry/agenda_council_proposal.md) and detect duplicate target fingerprints."
    );
    eprintln!(
        "  cargo xtask ministry-agenda sortition --roster <path> --slots <count> --seed <hex> [--out <path>]"
    );
    eprintln!(
        "    Generate a deterministic Agenda Council draw with Merkle proofs for audit (specs/ministry/agenda_council_proposal.md#sortition-cli)."
    );
    eprintln!(
        "  cargo xtask ministry-agenda impact [--proposal <path>]... [--proposal-dir <dir>]... [--registry <path>] [--policy-snapshot <path>] [--out <path>]"
    );
    eprintln!(
        "    Summarize proposal hash families, counting duplicate-registry hits and policy conflicts for MINFO-4b referendum packets."
    );
    eprintln!(
        "  cargo xtask ministry-panel synthesize --proposal <path> --volunteer <path> --ai-manifest <path> --panel-round <RP-YYYY-##> --output <path> [--language <tag> --generated-at <unix-ms>]"
    );
    eprintln!(
        "    Generate the review panel neutral summary + lint report for roadmap item MINFO-4a (specs/ministry/review_panel_summary.md)."
    );
    eprintln!(
        "  cargo xtask ministry-jury sortition --roster <path> --proposal <id> --round <id> --beacon <hex> --committee-size <count> --waitlist-size <count> --drawn-at <RFC3339> [--waitlist-ttl-hours <hours>] [--grace-period <secs>] [--failover-grace <secs>] [--out <path>]"
    );
    eprintln!(
        "    Produce a PolicyJurySortitionV1 manifest for roadmap item MINFO-5 (specs/ministry/policy_jury_ballots.md), wiring deterministic draws + waitlists into referendum packets."
    );
    eprintln!(
        "  cargo xtask kagami-bundle [--out <fresh-directory>] [--profile debug|release] [--network-profiles <artifact>]"
    );
    eprintln!("    Build matching Kagami and iroha3d together and inventory a native CLI package.");
    eprintln!(
        "  cargo xtask mochi-bundle [--out <path>] [--profile <name>] [--no-archive] [--network-profiles <path>] [--matrix <path>] [--smoke] [--stage <path>]"
    );
    eprintln!("  cargo xtask mochi-latency --bundle <directory> --out <new-sample-directory>");
    eprintln!("  cargo xtask mochi-latency-report --samples <directory> --out <new-report.json>");
    eprintln!(
        "  cargo xtask mochi-latency-remote --bundle <directory> --driver <release-test-executable> --out <new-campaign-directory>"
    );
    eprintln!("    Build the MOCHI desktop bundle with a manifest and optional .tar.gz archive.");
    eprintln!(
        "    Release requires committed defaults/developer/network-profiles.nrt; --network-profiles is development-only."
    );
    eprintln!(
        "    The bundler builds matching Mochi, Kagami and iroha3d together; latency commands observe an existing bundle and emit diagnostic samples only."
    );
    eprintln!(
        "    Use --matrix to append the bundle metadata to a JSON matrix (created if missing)."
    );
    eprintln!(
        "    Use --stage to copy the bundle (and archive when present) into a shared staging directory."
    );
    eprintln!(
        "    Use --smoke to verify packaged help, config-free source/bytecode/package deployment, live execution, and four-validator restart."
    );
    eprintln!(
        "  cargo xtask iso-bridge-lint [--isin <path>] [--bic-lei <path>] [--mic <path>] [--fixtures <path>]"
    );
    eprintln!(
        "    Lint ISO bridge reference data and fixture bundles (defaults to repository samples)."
    );
    eprintln!("  cargo xtask acceleration-state [--format table|json]");
    eprintln!(
        "    Print the applied acceleration configuration and Metal/CUDA runtime status to feed parity dashboards."
    );
}
