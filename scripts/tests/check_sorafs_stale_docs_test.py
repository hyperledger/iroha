"""Focused guards for canonical SoraFS V1 documentation claims."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from zk_source_tokens import rust_tokens

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 uses the existing test dependency
    import tomli as tomllib

from scripts.tests.sorafs_release_contract_support import release_module, required_release_kinds


REPO_ROOT = Path(__file__).resolve().parents[2]


def read(relative: str) -> str:
    """Read one checked-in UTF-8 source file."""

    return (REPO_ROOT / relative).read_text(encoding="utf-8")


def test_hedging_plan_uses_the_current_bridge_abi() -> None:
    plan = read("specs/sorafs_hedging_plan.md")
    bridge = read("crates/connect_norito_bridge/src/lib.rs")
    header = read("crates/connect_norito_bridge/include/connect_norito_bridge.h")
    privacy = read("crates/iroha_data_model/src/privacy/protocol.rs")

    source_match = re.search(
        r"CONNECT_NORITO_BRIDGE_ABI_VERSION:\s*u32\s*=\s*"
        r"PRIVACY_BRIDGE_ABI_VERSION_V1",
        bridge,
    )
    canonical_match = re.search(
        r"PRIVACY_BRIDGE_ABI_VERSION_V1:\s*u32\s*=\s*(\d+)",
        privacy,
    )
    header_match = re.search(
        r"#define\s+CONNECT_NORITO_BRIDGE_ABI_VERSION\s+(\d+)",
        header,
    )
    assert source_match is not None
    assert canonical_match is not None
    assert header_match is not None
    assert canonical_match.group(1) == header_match.group(1) == "31"
    assert "bridge source ABI is now 12" not in plan
    assert "sole first-release ABI, version 31" in plan


def test_reference_sdk_plan_does_not_reopen_native_orderbook_work() -> None:
    plan = read("specs/sorafs_reference_sdk_plan.md")
    normalized = " ".join(plan.split())
    checker = release_module("check_sorafs_reference_sdk_fixtures")
    payload_count = len(checker.EXPECTED_PAYLOADS)
    outcome_count = len(checker.EXPECTED_OUTCOMES)
    negative_count = sum(
        expectation != "valid"
        for _, _, _, expectation in checker.EXPECTED_PAYLOADS.values()
    )
    # Every repeated inventory claim must match the executable signed-inventory owner.
    count_claims = (
        (r"(\d+) payload artifacts", payload_count, 4),
        (r"(\d+) `ValidationOutcomeV1` (?:outcomes|files)", outcome_count, 2),
        (r"(\d+) exact outcome files", outcome_count, 1),
        (r"(\d+) outcomes", outcome_count, 1),
        (r"(\d+) negative payload vectors", negative_count, 4),
    )
    for pattern, expected, occurrences in count_claims:
        claims = re.findall(pattern, normalized)
        assert len(claims) == occurrences, pattern
        assert all(int(claim) == expected for claim in claims), (pattern, claims)

    assert (
        "runtime matcher service wiring, durable escrow mutation, and signature "
        "authorization remain"
    ) not in normalized
    assert "release-wide signed fixture inventory" not in normalized
    assert "The published and sealed cross-domain fixture inventory" not in normalized
    for marker in (
        "authoritative native ledger and supervised worker now own bounded "
        "price-time matching",
        "atomic custody mutation",
        "authority/signature enforcement",
        "The checked-in, test-only signed and sealed cross-domain fixture "
        f"inventory binds {payload_count} payload artifacts",
        f"{payload_count} payload artifacts",
        f"{outcome_count} `ValidationOutcomeV1` outcomes",
        f"{outcome_count} `ValidationOutcomeV1` files",
        f"{negative_count} negative payload vectors",
        "twelve exact parity profiles",
        "All eight generated `CancelAssetLock` positive/negative files are "
        "checked in",
        "The 85-byte canonical frame is byte-exact",
        "redundant 86-byte `0x21 0x20 <hash>` representation",
        "JavaScript/TypeScript, Python, Swift, Kotlin/JVM, mirrored Java "
        "Android, and C#",
        "published per-target archives and binding packages",
        "genuine downstream install/smoke evidence",
    ):
        assert marker in normalized


def test_fixture_readmes_do_not_claim_native_or_provider_qualification() -> None:
    provider = " ".join(
        read("fixtures/sorafs_manifest/provider_admission/README.md").split()
    )
    cookbook = " ".join(
        read("fixtures/documentation/sorafs_reference_sdk/README.md").split()
    )

    assert "exercise chunk scheduling end-to-end" not in provider
    assert (
        "These fixtures do not provide or qualify authenticated multi-provider "
        "transport, a governance-aware external software completion signer, a sealed-CAS "
        "retention backend, or four-validator deployment evidence."
        in provider
    )
    assert (
        "It is not evidence of clean ABI-30 builds for all five native release "
        "targets, skip-free SDK parity, published packages, external software signing, "
        "a qualified provider deployment, or L1/L2 promotion."
        in cookbook
    )


def test_gateway_tls_docs_require_withdrawal_and_runtime_adapter_recovery() -> None:
    handbook = read("specs/sorafs_gateway_deployment_handbook.md")
    automation = read("specs/sorafs_gateway_tls_automation.md")
    combined = f"{handbook}\n{automation}"

    assert "sorafs-gateway tls renew" not in combined
    assert "fall back to stored cert" not in combined
    assert "Withdraw the affected gateway" in handbook
    assert "audited runtime ACME adapter and controller boundary" in handbook
    assert "There is no production repository renewal" in automation
    assert (
        "Repository tooling neither issues nor installs production certificates"
        in automation
    )


def _rust_struct_fields(relative: str, name: str) -> dict[str, str]:
    source = read(relative)
    structure = re.search(rf"pub struct {name} \{{(.*?)\n\}}", source, re.DOTALL)
    assert structure is not None, name
    return dict(re.findall(r"pub ([a-z_]+): ([^,\n]+)", structure.group(1)))


def test_stream_token_docs_use_the_runtime_signer_hard_cut() -> None:
    paths = (
        "specs/sorafs_node_client_protocol.md",
        "specs/sorafs_gateway_chunk_range.md",
        "specs/sorafs_gateway_deployment_handbook.md",
        "specs/sorafs_gateway_operator_playbook.md",
    )
    documents = [read(path) for path in paths]
    active = "\n".join(documents)
    normalized_active = " ".join(active.split())
    for stale in (
        "SORAFS_STREAM_TOKENS_ENABLED", "token_signing_sk", "signing_key_path",
        "when the signing key is not configured", "sign_with_seed",
        "signer_handle =", "signer_public_key_hex =", "signer_revision =",
        "signer_policy_digest_hex =", "key_version =", "StreamTokenRuntimeSigner",
        "BareRuntimeSigner", "external software signer probes", "both exact startup qualification probes",
    ):
        assert stale not in active
    for marker in (
        "only when issuance is disabled in node TOML",
        "No signing-seed file, key path, or environment enablement is accepted",
        "There is no environment-variable enablement or signing-seed path",
    ):
        assert marker in normalized_active
    for document in documents:
        assert "sorafs/stream_token_signer_custody.md" in document
    actual = "crates/iroha_config/src/parameters/actual.rs"
    fields = _rust_struct_fields(actual, "SorafsTokenConfig")
    assert fields["signer"] == "Option<SorafsStreamTokenSignerConfig>"
    assert fields.keys().isdisjoint({
        "signer_handle", "signer_public_key", "signer_revision", "signer_policy_digest",
        "key_version", "signing_key_path", "token_signing_sk", "signing_seed",
    })
    signer = _rust_struct_fields(
        "crates/iroha_config/src/parameters/actual/stream_token_signer.rs",
        "SorafsStreamTokenSignerConfig",
    )
    assert set(signer) == {
        "runtime_handle", "key_handle", "service_id", "administrator_id", "public_key",
        "key_revision", "policy_revision", "policy_digest", "attester", "observer",
        "clock_uncertainty_ms", "native",
    }
    assert signer["attester"] == "SorafsStreamTokenAttesterConfig"
    assert signer["observer"] == "SorafsStreamTokenObserverConfig"
    assert signer["native"] == "Option<SorafsStreamTokenNativeConfig>"
    assert signer["clock_uncertainty_ms"] == "u64"
    user = _rust_struct_fields("crates/iroha_config/src/parameters/user.rs", "SorafsStreamTokenConfig")
    assert user["signer"] == "SorafsStreamTokenSignerConfig"
    assert "key_version" not in user


def test_stream_token_template_names_every_required_independent_signer_pin() -> None:
    path = "specs/sorafs/snippets/stream_token_signer_binding.toml"
    template = tomllib.loads(read(path))
    storage = template["sorafs"]["storage"]
    tokens = storage["stream_tokens"]
    signer = tokens["signer"]
    child = "crates/iroha_config/src/parameters/user/stream_token_signer.rs"
    names = {"signer": "SorafsStreamTokenSignerConfig", "attester": "SorafsStreamTokenAttesterConfig",
             "observer": "SorafsStreamTokenObserverConfig", "native": "SorafsStreamTokenNativeConfig"}
    assert set(signer) == set(_rust_struct_fields(child, names["signer"]))
    for role in ("attester", "observer", "native"):
        assert set(signer[role]) == set(_rust_struct_fields(child, names[role]))
    assert len(signer) - 3 + sum(len(signer[role]) for role in ("attester", "observer", "native")) == 37
    assert signer["clock_uncertainty_ms"] == 250
    assert signer["native"]["timeout_ms"] == 30000
    assert "provider_id_hex" in storage and "provider_id_hex" not in signer
    assert "key_version" not in tokens
    identities = [role[field] for role in (signer, signer["attester"], signer["observer"])
                  for field in ("service_id", "administrator_id")]
    assert len(set(identities)) == 6
    assert len({role["public_key_hex"] for role in (signer, signer["attester"], signer["observer"])}) == 3
    # The template is intentionally not ready-to-run trust or fabricated qualification.
    assert all(role["key_revision"] == role["policy_revision"] == 0
               for role in (signer, signer["attester"], signer["observer"]))
    assert signer["attester"]["active_from_unix_ms"] == signer["attester"]["active_until_unix_ms"] == 0
    assert signer["observer"]["active_from_unix_ms"] == signer["observer"]["active_until_unix_ms"] == 0
    contract = " ".join(read("specs/sorafs/stream_token_signer_custody.md").split())
    for marker in ("deliberately invalid", "all six service/administrator", "all three public keys",
                   "86,400,000 ms", "300,000 ms", "independent approved anchor",
                   "configured signer provider", "current finalized-state observer",
                   "coherent native", "do not complete those qualification outcomes"):
        assert marker.lower() in contract.lower()


def test_stream_token_runtime_has_separate_trust_and_one_body_recovery_owners() -> None:
    prefix = "crates/iroha_torii/src/sorafs/token/"
    transport = read(prefix + "signer_transport.rs")
    lifecycle = read(prefix + "signer_lifecycle.rs")
    assert '#[path = "signer_completed_phase.rs"]' in lifecycle
    assert "mod completed_phase;" in lifecycle
    assert "completed_phase::Received::new(" in lifecycle
    completed = read(prefix + "signer_completed_phase.rs")
    finality = read(prefix + "signer_finality.rs")
    pins = read(prefix + "signer_pins.rs")
    issuer = read("crates/iroha_torii/src/sorafs/token.rs")
    exports = read("crates/iroha_torii/src/sorafs/mod.rs")
    builders = read("crates/iroha_torii/src/sorafs/stream_token_runtime.rs")
    for retired in ("trait StreamTokenRuntimeSigner", "StreamTokenRuntimeSignerQualificationV1", "BareRuntimeSigner"):
        assert retired not in transport + issuer + exports
    for owner in ("StreamTokenSignerClientV1", "StreamTokenStateObserverClientV1",
                  "StreamTokenApprovedCustodyAnchorV1", "StreamTokenSignerReceiptV1"):
        assert owner in transport and owner in exports
    for builder in ("with_sorafs_stream_token_signer_client", "with_sorafs_stream_token_state_observer",
                    "with_sorafs_stream_token_approved_anchor"):
        assert f"pub fn {builder}" in builders
    assert "Option<Arc<dyn StreamTokenSignerClientV1>>" in issuer
    assert "Option<Arc<dyn StreamTokenStateObserverClientV1>>" in issuer
    assert "Option<StreamTokenApprovedCustodyAnchorV1>" in issuer
    for phase in ("Startup", "BeforeProvider", "AfterCommit", "BeforeRelease"):
        assert f"Phase::{phase}" in lifecycle
    assert re.sub(r"\s+", "", lifecycle).count("self.client.sign(") == 1
    assert re.sub(r"\s+", "", lifecycle).count("self.client.recover(") == 1
    assert "StreamTokenSignerCallErrorV1::AmbiguousCompletion" in lifecycle
    for verifier in ("verify_stream_token_signer_current_evidence_v1", "verify_stream_token_signer_completed_observation_v1",
                     "verify_stream_token_signer_evidence_v1"):
        assert verifier in lifecycle
    assert ".continues_active_state(self.inputs.original)" in completed
    assert "HistoricalFinalityV1::Custody(marker.custody().statement().anchor)" in completed
    assert "HistoricalFinalityV1::Custody(phase.inputs.signing_anchor)" in completed
    core_finality = read("crates/iroha_core/src/query/signer_finality.rs")
    for marker in (
        "struct VerifiedFinalityTargetsV1<'view, V: StateReadOnly>",
        "targets.len() > 6",
        "target.height == 0 || target.block_hash == [0; 32]",
        "targets.sort_unstable_by_key(|target| target.height)",
        "let through = if first == 1 { last.max(2) } else { last }",
        "CertifiedChain::new(view)",
        "for block in reader.walk(first, through)",
        "block.height() > 1 && block.verification() != QcVerification::Verified",
        "target.block_hash != *block.block_hash().as_ref()",
        "if matched != targets.len()",
        "batched_finality_requires_certified_genesis_successor",
        "batched_finality_bounds_targets_before_walking",
        "vec![valid, conflicting]",
        "vec![conflicting, valid]",
    ):
        assert marker in finality
    certified_chain = read("crates/iroha_core/src/sumeragi/certified_chain.rs")
    assert "CertifiedChain::new(view)" in core_finality and ".certified(height)" in core_finality
    assert "block.block_hash().as_ref() != block_hash" in core_finality
    certified_tokens = "".join(rust_tokens(certified_chain))
    assert "".join(rust_tokens("read_durable_pinned_block(view.kura(), index, *expected, &view.execution_budget())")) in certified_tokens
    durable_start = certified_chain.index("\nfn read_durable_pinned_block_bounded(")
    durable_end = certified_chain.index("\npub struct CertifiedChain", durable_start)
    durable_tokens = "".join(rust_tokens(certified_chain[durable_start:durable_end]))
    for contract in (
        ".read(wire_len, budget)",
        ".native_frame_read(height, expected)",
        "iroha_data_model::block::decode_framed_signed_block(&bytes)",
        "block.hash() != expected || block.header().height().get() != height",
    ):
        assert "".join(rust_tokens(contract)) in durable_tokens
    assert "index.get() <= view.block_hashes().len()" in certified_chain
    for contract in (
        "iroha_sumeragi::crypto::Verifier::new(",
        "&authority.crypto", "&authority.committee", ".verify_qc(verifier, commit_qc)",
        "commit_qc.height != height", "commit_qc.block_hash != committed.core_hash",
        "self.verify_commit_qc_original(&committed, authority, &commit_qc)?",
        "verify_availability(&committed, config, &authority.crypto, availability, admit_scratch,)?",
    ):
        assert "".join(rust_tokens(contract)) in certified_tokens
    assert "v2_finality_artifact(" not in core_finality
    assert "view.block_hashes()" in finality
    assert "stream_token_binding_digest_v1(&binding)" in pins
    assert "u32::try_from(signer_backend.key_revision)" in pins
    assert "norito::encode_canonical(token)" in issuer
    assert "norito::decode_canonical_with_limits" in issuer
    assert "norito::to_bytes(token)" not in issuer
    assert "fn validate_token_body" not in issuer
    shared = read("crates/sorafs_manifest/src/token.rs")
    assert "pub fn validate_token_body" in shared
    assert re.search(r"STREAM_TOKEN_MAX_WIRE_BYTES_V1:\s*usize\s*=\s*2_048", shared)
    producer = read("crates/irohad/src/signer_operation/stream_token.rs")
    assert "prepare_stream_token_signing_payload_v1" in producer
    assert "SignerReceiptPurposeV1::StreamToken" in producer
    assert "pub fn recover(" in producer
    native = read("crates/iroha_config/tests/sorafs_stream_token_runtime_signer/signer_config_tests.rs")
    for witness in ("rejects_incomplete_disabled_and_non_production_forms", "rejects_noncanonical_or_invalid_ed25519_keys",
                    "provider_is_required_once_and_obsolete_flat_signer_fields_have_no_aliases", "independent"):
        assert witness in native
    config_regressions = read("crates/iroha_config/tests/sorafs_stream_token_runtime_signer.rs")
    assert "signing_key_path" in config_regressions
    assert "SORAFS_STREAM_TOKENS_ENABLED" in config_regressions
    assert "sorafs_configuration_has_no_production_environment_bindings" in config_regressions


def test_gateway_release_contract_uses_catalog_authority() -> None:
    checker = release_module("check_sorafs_gateway_compliance_rollout_evidence")
    contract = release_module("sorafs_production_readiness_contract")
    assert "catalog_promotion" in required_release_kinds("gateway_compliance")
    assert {"catalog_entries", "catalog_changes", "catalog_signatures_verified"} <= set(
        checker.EVIDENCE_REQUIRED_FIELDS["catalog_promotion"]
    )
    assert (
        contract.PAYLOAD_FREE_SUMMARY_FINGERPRINT_HEX_LIST_BINDINGS["valid_catalog_digests"]
        == "catalog_digest_hex"
    )
    assert {"min_catalog_entries", "min_catalog_changes"} <= checker.ValidationOptions.__dataclass_fields__.keys()
    for kind, fields in checker.EVIDENCE_REQUIRED_FIELDS.items():
        assert kind not in {"feed-promotion", "appeal-override"}
        assert set(fields).isdisjoint({"denylist_entry_count", "denylist_entries", "valid_bundle_digests"})


def test_future_dated_seaglass_reports_are_not_readiness_evidence() -> None:
    reports_dir = REPO_ROOT / "specs/ministry/reports"
    status = read("specs/ministry/red_team_status.md")
    normalized_status = " ".join(status.split())

    assert not list(
        reports_dir.glob("2026-08-mod-red-team-operation-seaglass*.md")
    )
    for stale in (
        "SeaGlass",
        "Operation SeaGlass",
        "MINFO-RT-17",
        "MINFO-RT-18",
        "2026-08-18",
    ):
        assert stale not in status
    for marker in (
        "no completed genuine moderation red-team drill",
        "Only genuine runtime evidence may populate a completed-drill row",
        "Passing that structural guard does not verify referenced artefacts",
    ):
        assert marker in normalized_status


@pytest.mark.parametrize("old,new", (
    ("read_durable_pinned_block(view.kura(), index, *expected, &view.execution_budget())", "read_durable_pinned_block(view.kura(), index, *expected, &other_budget)"),
    (".read(wire_len, budget)", ".read(wire_len, other_budget)"),
    ("self.verify_commit_qc_original(&committed, authority, &commit_qc)?", "skip_commit_qc_original(&committed, authority, &commit_qc)?"),
    (".native_frame_read(height, expected)", ".native_frame_read(height, other_hash)"),
    ("iroha_data_model::block::decode_framed_signed_block(&bytes)", "decode_local_cached_body(&bytes)"),
    ("block.hash() != expected || block.header().height().get() != height", "block.hash() != expected"),
    (".verify_qc(verifier, commit_qc)", ".skip_qc(verifier, commit_qc)"),
    ("verify_availability(\n            &committed,", "skip_availability(\n            &committed,"),
))
def test_stream_token_finality_requires_actual_durable_certificate_and_signed_availability(monkeypatch, old, new):
    """A source guard must refuse dropped native frame, exact height, QC or availability checks."""
    test_stream_token_runtime_has_separate_trust_and_one_body_recovery_owners()
    original_read = read
    path = "crates/iroha_core/src/sumeragi/certified_chain.rs"
    source = original_read(path)
    assert old in source
    if old.startswith((".native_frame_read(", ".read(wire_len,", "iroha_data_model::block::decode_framed_signed_block(", "block.hash() !=")):
        start = source.index("\nfn read_durable_pinned_block_bounded(")
        end = source.index("\npub struct CertifiedChain", start)
        owner = source[start:end]
        assert owner.count(old) == 1
        changed = source[:start] + owner.replace(old, new, 1) + source[end:]
    else:
        assert source.count(old) == 1
        changed = source.replace(old, new, 1)
    monkeypatch.setattr(__import__(__name__, fromlist=["read"]), "read",
                        lambda relative: changed if relative == path else original_read(relative))
    with pytest.raises(AssertionError):
        test_stream_token_runtime_has_separate_trust_and_one_body_recovery_owners()
