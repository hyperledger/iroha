.PHONY: dev-workflow check-agents-guardrails check-dependency-discipline check-status-sync check-std-only check-missing-docs check-tests-guard check-todo-guard check-env-config-surface check-serde-guard check-telemetry-redaction-guard check-proc-macro-ui check-iroha-monitor-docs check-iroha-monitor-screenshots monitor-screenshots agents-preflight check-axt-fixtures check-docs-tests-metrics
.PHONY: examples examples-run examples-inspect docs-syscalls docs-da-threat-model check-docs guards swift-dashboards swift-docs-lint
.PHONY: gost-bench gost-bench-update gost-dudect
.PHONY: docs-cli docs-kagami-cli
.PHONY: norito-matrix norito-matrix-downstream
.PHONY: check-fhe-ownership refresh-fhe-ownership check-fhe-bgv-cost refresh-fhe-bgv-cost
.PHONY: check-fastpq-row-usage check-fastpq-rollout check-nexus-lanes check-sns-annex
.PHONY: bridge-xcframework bridge-checksum
.PHONY: docs-syscalls
.PHONY: android-fixtures-check
.PHONY: android-tests android-lint android-transport-guard android-publish-snapshot kotlin-reflection-guard
.PHONY: swift-fixtures-check swift-ci swift-status
.PHONY: python-checks
.PHONY: python-release-smoke
.PHONY: python-fixtures-check
.PHONY: build
.PHONY: kotodama-goldens kotodama-goldens-check

KOTO?=koto
IVM?=ivm_run
# Default downstream crate for Norito feature matrix local runs
CRATE?=iroha_data_model

# Swift dashboard thresholds (override via environment if needed)
SWIFT_PARITY_MAX_OLDEST_HOURS?=336
SWIFT_PARITY_MAX_REGEN_HOURS?=48
SWIFT_CI_PARITY_LANE?=ci/xcode-swift-parity
SWIFT_CI_PARITY_MIN_SUCCESS?=0.95
SWIFT_CI_MAX_CONSEC_FAIL?=1
SWIFT_PARITY_ACCEL_REQUIRE?=metal=pass neon=pass
SWIFT_PARITY_ACCEL_REQUIRE_ENABLED?=metal neon
SWIFT_CI_METAL_MIN_SPEEDUP?=2.0
SWIFT_CI_NEON_MIN_THROUGHPUT?=500
SWIFT_PARITY_FEED?=dashboards/data/mobile_parity.sample.json
SWIFT_CI_FEED?=dashboards/data/mobile_ci.sample.json
SWIFT_PIPELINE_METADATA_FEED?=dashboards/data/mobile_pipeline_metadata.sample.json

build:
	@bash scripts/build_canonical_binaries.sh

dev-workflow:
	@bash scripts/dev_workflow.sh

check-agents-guardrails:
	@bash ci/check_agents_guardrails.sh

check-dependency-discipline:
	@bash ci/check_dependency_discipline.sh

check-missing-docs:
	@bash ci/check_missing_docs_guard.sh

check-tests-guard:
	@bash ci/check_tests_guard.sh

check-docs-tests-metrics:
	@bash ci/check_docs_tests_metrics_guard.sh

check-todo-guard:
	@bash ci/check_todo_guard.sh

check-status-sync:
	@bash ci/check_status_sync.sh

agents-preflight:
	@bash ci/check_agents_guardrails.sh
	@bash ci/check_missing_docs_guard.sh
	@bash ci/check_tests_guard.sh
	@bash ci/check_docs_tests_metrics_guard.sh
	@bash ci/check_todo_guard.sh
	@bash ci/check_status_sync.sh
	@bash ci/check_dependency_discipline.sh
	@bash ci/check_std_only.sh
	@bash ci/check_env_config_surface.sh
	@bash ci/check_serde_guard.sh
	@bash ci/check_telemetry_redaction_guard.sh
	@bash ci/check_iroha_monitor_assets.sh
	@bash ci/check_iroha_monitor_screenshots.sh
	@bash ci/check_axt_fixtures.sh
	@$(MAKE) guards

check-std-only:
	@bash ci/check_std_only.sh

check-env-config-surface:
	@bash ci/check_env_config_surface.sh

check-serde-guard:
	@bash ci/check_serde_guard.sh

check-telemetry-redaction-guard:
	@bash ci/check_telemetry_redaction_guard.sh

check-axt-fixtures:
	@bash ci/check_axt_fixtures.sh

check-iroha-monitor-docs:
	@bash ci/check_iroha_monitor_assets.sh
	@bash ci/check_iroha_monitor_screenshots.sh

check-iroha-monitor-screenshots:
	@bash ci/check_iroha_monitor_screenshots.sh

monitor-screenshots:
	@bash scripts/iroha_monitor_demo.sh

check-proc-macro-ui:
	@bash ci/check_proc_macro_ui.sh

kotodama-goldens:
	@python3 scripts/regenerate_kotodama_goldens.py --write \
		--output-root "$${IROHA_KOTODAMA_V1_ARTIFACT_STAGE:?set an absent absolute publication root under ignored target or outside the workspace}"

kotodama-goldens-check:
	@python3 scripts/regenerate_kotodama_goldens.py --check

examples:
	@echo "Available examples:"
	@echo "  - examples/hello/hello.ko"
	@echo "  - examples/transfer/transfer.ko"

examples-run:
	@command -v $(KOTO) >/dev/null 2>&1 || { echo "Missing $(KOTO). Set KOTO=<path> or install on PATH."; exit 1; }
	@command -v $(IVM) >/dev/null 2>&1 || { echo "Missing $(IVM). Set IVM=<path> or install on PATH."; exit 1; }
	@mkdir -p target/examples
	$(KOTO) build examples/hello/hello.ko --out target/examples/hello.to
	$(IVM) target/examples/hello.to --args '{}'
	$(KOTO) build examples/transfer/transfer.ko --out target/examples/transfer.to
	$(IVM) target/examples/transfer.to --args '{}'
	$(KOTO) build examples/nft/nft.ko --out target/examples/nft.to
	$(IVM) target/examples/nft.to --args '{}'

examples-inspect: examples-run
	@command -v ivm_tool >/dev/null 2>&1 || { echo "Missing ivm_tool. Install or set IVM_TOOL_BIN and run the ignored integration test."; exit 1; }
	ivm_tool inspect target/examples/hello.to
	ivm_tool inspect target/examples/transfer.to
	ivm_tool inspect target/examples/nft.to

docs-syscalls:
	@python3 scripts/gen_syscall_doc.py --write
	@echo "Generated specs/ivm_syscalls_generated.md"

docs-da-threat-model:
	@echo "Generating DA threat-model report JSON..."
	@scripts/telemetry/run_da_threat_model_report.sh specs/da/_generated
	@echo "Updating specs/da/threat_model.md..."
	@python3 scripts/docs/render_da_threat_model_tables.py \
		--input specs/da/_generated/threat_model_report.json \
		--docs specs/da/threat_model.md
	@echo "DA threat-model docs refreshed."

check-docs:
	@bash scripts/check_syscalls_doc.sh

# Build NoritoBridge.xcframework and a reproducible zip + checksum for SPM.
# MOBILE_SDK_CARGO_LOCKFILE selects the owned canonical external read-only graph;
# the builder authenticates it against the committed repository Cargo.lock.
bridge-xcframework:
	@test -n "$$SOURCE_DATE_EPOCH" || { echo "SOURCE_DATE_EPOCH is required" >&2; exit 1; }
	@test -n "$$NORITO_BRIDGE_OUT_DIR" || { echo "NORITO_BRIDGE_OUT_DIR is required" >&2; exit 1; }
	@test -n "$$NORITO_BRIDGE_BUILD_DIR" || { echo "NORITO_BRIDGE_BUILD_DIR is required" >&2; exit 1; }
	@test -n "$$NORITO_BRIDGE_ARCHIVE_OUTPUT" || { echo "NORITO_BRIDGE_ARCHIVE_OUTPUT is required" >&2; exit 1; }
	@test -n "$$MOBILE_SDK_CARGO_LOCKFILE" || { echo "MOBILE_SDK_CARGO_LOCKFILE is required" >&2; exit 1; }
	@bash scripts/build_norito_xcframework.sh \
		--lockfile-path "$$MOBILE_SDK_CARGO_LOCKFILE" \
		--archive-output "$$NORITO_BRIDGE_ARCHIVE_OUTPUT"
	@$(MAKE) bridge-checksum

bridge-checksum:
	@test -n "$$NORITO_BRIDGE_ARCHIVE_OUTPUT" || { echo "NORITO_BRIDGE_ARCHIVE_OUTPUT is required" >&2; exit 1; }
	@echo "SPM checksum for $$NORITO_BRIDGE_ARCHIVE_OUTPUT:"
	@if command -v swift >/dev/null 2>&1; then \
		swift package compute-checksum "$$NORITO_BRIDGE_ARCHIVE_OUTPUT"; \
	else \
		shasum -a 256 "$$NORITO_BRIDGE_ARCHIVE_OUTPUT" | awk '{print $$1}'; \
	fi

# Run serialization guards locally (deny direct serde/serde_json, ad-hoc AoS/NCB helpers)
guards:
	@bash scripts/deny_serde_json.sh
	@bash scripts/check_no_direct_serde.sh
	@bash scripts/deny_handrolled_aos.sh
	@bash scripts/check_no_legacy_codec.sh
	@python3 scripts/check_first_release_history.py
	@python3 scripts/check_zk_x509_presentation_interval.py
	@python3 scripts/check_zk_resource_contract.py
	@python3 scripts/fhe_bgv_cost_model.py
	@python3 crates/iroha_fhe/tests/vectors/bgv_reference.py --check
	@python3 scripts/check_zk_runtime_validity.py
	@python3 scripts/check_zk_operation_inventory.py
	@python3 scripts/check_zk_economic_invariants.py
	@python3 scripts/check_zk_primitive_workloads.py
	@python3 scripts/check_state_commitment_candidates.py
	@bash scripts/check_contract_address_chain_identity.sh

# Check the FHE ownership inventory (specs/fhe_ownership_inventory.json) against the tree.
check-fhe-ownership:
	@python3 -I -S scripts/check_fhe_ownership_map.py
	@python3 -m unittest scripts/tests/check_fhe_ownership_map_test.py

# Recompute the derived facts of the FHE ownership inventory; classifications are kept.
refresh-fhe-ownership:
	@python3 -I -S scripts/check_fhe_ownership_map.py --refresh --write

# Check the RNS-BGV cost summary (specs/fhe_bgv_cost_summary.json), the view of it that
# `cargo test -p iroha_fhe --test bgv_cost_model_vectors` recomputes, the tables the
# specifications embed and the independent known-answer vectors.
check-fhe-bgv-cost:
	@python3 -I -S scripts/fhe_bgv_cost_model.py
	@python3 -I -S crates/iroha_fhe/tests/vectors/bgv_reference.py --check
	@python3 -m unittest scripts/tests/fhe_bgv_cost_model_test.py

# Recompute every derived block of the cost summary from the measured runs it holds, and
# rewrite the view and the embedded tables. Measured values are kept.
refresh-fhe-bgv-cost:
	@python3 -I -S scripts/fhe_bgv_cost_model.py --rederive --write

# Run a local subset of the Norito feature matrix (use --fast for fewer cases)
norito-matrix:
	@bash scripts/run_norito_feature_matrix.sh --fast

# Run the fast Norito matrix and include a downstream smoke per combo.
# Override: `make norito-matrix-downstream CRATE=<crate>`
norito-matrix-downstream:
	@bash scripts/run_norito_feature_matrix.sh --fast --downstream $(CRATE)

norito-enum-bench-ci:
	@bash ci/check_norito_enum_bench.sh

check-fastpq-row-usage:
	@bash ci/check_fastpq_row_usage.sh

check-fastpq-rollout:
	@bash ci/check_fastpq_rollout.sh

check-nexus-lanes:
	@bash ci/check_nexus_lane_smoke.sh
	@bash ci/check_nexus_lane_registry_bundle.sh

check-sm-perf:
	@bash ci/check_sm_perf.sh

check-ministry-transparency:
	@bash ci/check_ministry_transparency.sh

check-sorafs-adoption:
	@bash ci/check_sorafs_orchestrator_adoption.sh

check-sns-annex:
	@bash ci/check_sns_annex.sh

# Render Iroha CLI Markdown help from the live binary. Unlike Kagami's compact
# reference below, the full Iroha help is intentionally not checked in.
docs-cli:
	@cargo run -p iroha_cli -- tools markdown-help

docs-kagami-cli:
	@echo "Regenerating kagami CLI Markdown help..."
	@cargo run -p iroha_kagami -- advanced markdown-help > crates/iroha_kagami/CommandLineHelp.md
	@echo "Done: crates/iroha_kagami/CommandLineHelp.md"

# Run GOST perf benchmark + tolerance check.
GOST_BENCH_ARGS ?=

gost-bench:
	@./scripts/gost_bench.sh $(GOST_BENCH_ARGS)

gost-bench-update:
	@./scripts/gost_bench.sh --write-baseline $(GOST_BENCH_ARGS)

gost-dudect:
	cargo test -p iroha_crypto --features gost -- gost_sign_constant_time_under_dudect

swift-dashboards:
	@python3 scripts/check_swift_dashboard_data.py \
		--parity-max-oldest-hours $(SWIFT_PARITY_MAX_OLDEST_HOURS) \
		--parity-max-regen-hours $(SWIFT_PARITY_MAX_REGEN_HOURS) \
		--parity-require-no-breach \
		$(foreach req,$(SWIFT_PARITY_ACCEL_REQUIRE), --parity-accel-require $(req)) \
		$(foreach backend,$(SWIFT_PARITY_ACCEL_REQUIRE_ENABLED), --parity-accel-require-enabled $(backend)) \
		--ci-lane-threshold "$(SWIFT_CI_PARITY_LANE)>=$(SWIFT_CI_PARITY_MIN_SUCCESS)" \
		--ci-max-consecutive-failures $(SWIFT_CI_MAX_CONSEC_FAIL) \
		$(if $(SWIFT_CI_METAL_MIN_SPEEDUP), --ci-metal-min-speedup $(SWIFT_CI_METAL_MIN_SPEEDUP),) \
		$(if $(SWIFT_CI_NEON_MIN_THROUGHPUT), --ci-neon-min-throughput $(SWIFT_CI_NEON_MIN_THROUGHPUT),) \
		"$(SWIFT_PARITY_FEED)" "$(SWIFT_CI_FEED)"
	@python3 scripts/check_swift_pipeline_metadata.py "$(SWIFT_PIPELINE_METADATA_FEED)"
	@python3 -m jsonschema --output pretty specs/references/ios_metrics.schema.json --instance "$(SWIFT_PARITY_FEED)"
	@python3 -m jsonschema --output pretty specs/references/ios_metrics.schema.json --instance "$(SWIFT_CI_FEED)"
	@./scripts/render_swift_dashboards.sh "$(SWIFT_PARITY_FEED)" "$(SWIFT_CI_FEED)" "$(SWIFT_PIPELINE_METADATA_FEED)"

swift-fixtures-check:
	@python3 scripts/check_swift_fixtures.py

swift-ci: swift-fixtures-check swift-dashboards

swift-status:
	@python3 scripts/swift_status_export.py

swift-docs-lint:
	@python3 scripts/swift_doc_lint.py

python-fixtures-check:
	@python3 scripts/check_python_fixtures.py

python-checks:
	@./python/iroha_python/scripts/run_checks.sh

python-release-smoke:
	@bash python/iroha_python/scripts/release_smoke.sh

android-fixtures-check:
	@bash ci/check_android_fixtures.sh

android-tests:
	@bash ci/run_android_tests.sh

android-lint:
	@ANDROID_GRADLE_TASKS=":android:lint" bash ci/run_android_tests.sh

android-transport-guard:
	@bash ci/check_android_transport_guard.sh

kotlin-reflection-guard:
	@bash scripts/check_kotlin_no_reflection.sh

android-codegen-docs:
	@scripts/sumeragi_release_cargo_proxy.sh run --locked --offline -p norito_codegen_exporter --features dev-tools -- --out target-codex/android_codegen
	@python3 scripts/android_codegen_docs.py \
		--manifest target-codex/android_codegen/instruction_manifest.json \
		--builders target-codex/android_codegen/builder_index.json \
		--out specs/sdk/android/generated
	@python3 scripts/android_codegen_replay_sorafs_fixture.py
	@bash scripts/docs/hash_tree.sh \
		specs/sdk/android/generated \
		specs/sdk/android/generated/codegen_hash_tree.json

android-codegen-verify: android-codegen-docs
	@python3 scripts/check_android_codegen_parity.py \
		--manifest target-codex/android_codegen/instruction_manifest.json \
		--builder-index target-codex/android_codegen/builder_index.json \
		--metadata specs/sdk/android/generated/codegen_manifest_metadata.json \
		--json-out artifacts/android/codegen_parity_summary.json

android-publish-snapshot:
	@bash scripts/android_publish_snapshot.sh

# ZK delivery plan task F.4: build iroha_core under several Cargo feature
# selections and compare the validity record of one fixed scenario (certified
# history, policy identities, limit decisions and verification gas). Two long
# builds; not part of the default guards.
.PHONY: check-zk-feature-parity
check-zk-feature-parity:
	@python3 scripts/check_zk_feature_parity.py
