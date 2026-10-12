# Iroha VM + Kotodama Docs Index

This index links the main design and reference documents for IVM, Kotodama, and the IVM‑first pipeline.

- IVM architecture and language mapping: `../ivm.md`
- IVM syscall ABI: `ivm_syscalls.md`
- Generated syscall constants: `ivm_syscalls_generated.md` (run `make docs-syscalls` to refresh)
- IVM bytecode header: `ivm_header.md`
- Kotodama grammar and semantics: `kotodama_grammar.md`
- Kotodama examples and syscall mappings: `kotodama_examples.md`
- Machine-readable Kotodama V1 documentation policy: `kotodama_v1_docs.json`
- Transaction pipeline (IVM‑first): `../new_pipeline.md`
- Torii Contracts API (manifests): `torii_contracts_api.md`
- Universal account/UAID operations guide: `universal_accounts_guide.md`
- JSON query envelope (CLI / tooling): `query_json.md`
- Norito streaming module reference: `norito_streaming.md`
- Runtime ABI samples: `samples/runtime_abi_active.md`, `samples/runtime_abi_hash.md`, `samples/find_active_abi_versions.md`
- ZK App API (attachments, prover, vote tally): `zk_app_api.md`
- Torii ZK attachments/prover runbook: `zk/prover_runbook.md`
- Torii ZK App API operator guide (attachments/prover; crate doc): `../crates/iroha_torii/docs/zk_app_api.md`
- Torii MCP API guide (agent/tool bridge; crate doc): `../crates/iroha_torii/docs/mcp_api.md`
- VK/proof lifecycle (registry, verification, telemetry): `zk/lifecycle.md`
- Torii Operator Aids (endpoints for visibility): `references/operator_aids.md`
- Nexus default-lane quickstart: `quickstart/default_lane.md`
- MOCHI supervisor quickstart & architecture: `mochi/index.md`
- JavaScript SDK guides (quickstart, configuration, publishing): `sdk/js/index.md`
- Swift SDK parity/CI dashboards: `references/ios_metrics.md`
- Governance: `../gov.md`
- Domain endorsements (committees, policies, validation): `domain_endorsements.md`
- JDG attestations (offline validation tooling): `jdg_attestations.md`
- Clarification coordination prompts: `coordination_llm_prompts.md`
- Roadmap: `../roadmap.md`
- Docker builder image usage: `docker_build.md`

Usage tips
- Check and build sources in `examples/` with the unified `koto` driver.
- Exercise a named entrypoint with `iroha contract debug-call`, or a view
  with `iroha contract debug-view`. Pair `--source-file` with the matching
  hash-bound `--source-map-file` emitted by the same `koto build`; the debugger
  rejects a source-map sidecar for a different artifact.
- Optional integration tests (ignored by default) for examples and header checks live in `integration_tests/tests/`.

Pipeline configuration
- All runtime behavior is configured via `iroha_config` files. Environment variables are not used for operators.
- Sensible defaults are provided; most deployments won’t need changes.
- Relevant keys under `[pipeline]`:
  - Execution limits and the access-set derivation mode (`dynamic_prepass`, overlay bounds, IVM cycle and decoded-program bounds, quarantine, query and AMX limits) are not keys of this section: they are the committed chain parameter `pipeline_validity_policy_v1`.
  - `access_set_cache_enabled`: cache derived access sets per `(code_hash, entrypoint)`; disable to debug hints (default: true).
  - `parallel_overlay`: build overlays in parallel; commit remains deterministic (default: true).
  - `gpu_key_bucket`: optional key bucketing for the scheduler prepass using a stable radix on `(key, tx_idx, rw_flag)`; deterministic CPU fallback is always active (default: false).
  - `cache_size`: capacity of the global IVM pre‑decode cache (decoded streams kept). Default: 128. Increasing can reduce decode time for repeated executions.

Docs sync checks
- Syscall constants (specs/ivm_syscalls_generated.md)
  - Regenerate: `make docs-syscalls`
  - Check only: `bash scripts/check_syscalls_doc.sh`
- Syscall ABI table (crates/ivm/docs/syscalls.md)
  - Check only: `cargo run -p ivm --features dev-tools --bin gen_syscalls_doc -- --check`
  - Update generated section (and code docs table): `cargo run -p ivm --features dev-tools --bin gen_syscalls_doc -- --write`
- Pointer‑ABI tables (crates/ivm/docs/pointer_abi.md and ivm.md)
  - Check only: `cargo run -p ivm --features dev-tools --bin gen_pointer_types_doc -- --check`
  - Update sections: `cargo run -p ivm --features dev-tools --bin gen_pointer_types_doc -- --write`
- IVM header policy, ABI hashes, and runtime hash samples
  (`specs/ivm_header*.md`, `specs/samples/runtime_abi_hash*.md`)
  - Check only: `cargo run -p ivm --features dev-tools --bin gen_header_doc -- --check` and `cargo run -p ivm --features dev-tools --bin gen_abi_hash_doc -- --check`
  - Update sections: `cargo run -p ivm --features dev-tools --bin gen_header_doc -- --write` and `cargo run -p ivm --features dev-tools --bin gen_abi_hash_doc -- --write`

CI
- Pull-request CI discovers every tracked Kotodama source fence and documented
  `*.ko` heredoc below the roots in `kotodama_v1_docs.json`, then checks the
  unique sources with the canonical Rust driver. Run the same guard locally
  with `python3 scripts/check_kotodama_docs.py --koto target/debug/koto`.
- Generated syscall documentation drift is checked with the commands above.
- [Governance Playbook](governance_playbook.md)
