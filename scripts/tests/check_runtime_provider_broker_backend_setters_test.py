"""Source contract for the runtime-provider broker backend inventory and setters."""

from __future__ import annotations

import hashlib
import json
import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
API_PATH = REPO_ROOT / "crates" / "irohad" / "src" / "runtime_provider_broker" / "api.rs"
MACRO_NAME = "define_runtime_provider_backends_v1"
INVOCATION_MARKER = f"{MACRO_NAME}! {{"
BACKEND_STRUCT_MARKER = "pub struct RuntimeProviderBrokerBackendsV1 {"
EXPECTED_OPTIONAL_METHODS = (
    "with_bootle_lantern_issuance",
    "with_moderation_quarantine_key_wrapper",
    "with_privacy_cycle_prf_provider",
    "with_privacy_release_anchor",
    "with_transparency_leader_lease_provider",
    "with_fenced_privacy_publisher",
    "with_fenced_privacy_head_reader",
    "with_governance_dag_signer",
    "with_governance_dag_ipfs_authenticator",
    "with_governance_dag_head_authenticator",
    "with_governance_dag_checkpoint_store",
    "with_stream_token_signer_client",
    "with_stream_token_state_observer",
    "with_appeal_finance_checkpoint",
    "with_proof_outcome_transaction_signer",
    "with_repair_transaction_signer",
    "with_reserve_transaction_signer",
    "with_orderbook_transaction_signer",
    "with_moderation_transaction_signer",
    "with_moderation_settlement_handoff",
    "with_moderation_publication_handoff",
    "with_moderation_panel_notification",
    "with_moderation_checkpoint_store",
    "with_moderation_panel_notification_archive",
    "with_provider_ingest_authenticated_source",
    "with_provider_ingest_signer_resolver",
    "with_provider_ingest_checkpoint_store",
    "with_provider_ingest_retention_authority",
    "with_reputation_finalized_archive_retention_authority",
    "with_reputation_journal_transaction_submitter",
    "with_reputation_journal_checkpoint",
    "with_reputation_threshold_signer",
    "with_reputation_governance_dag",
    "with_billing_finalized_query",
    "with_billing_journal_verifier",
    "with_billing_statement_signer",
    "with_billing_statement_publisher",
    "with_billing_acknowledgement_authority",
    "with_billing_epoch_witness_store",
    "with_pop_credential_provider_registry",
    "with_potr_gateway_signer",
    "with_potr_provider_signer",
    "with_gateway_acme_client",
    "with_gateway_compliance_feed_transport",
    "with_por_finalized_replay_archive",
    "with_evidence_viewer_webauthn",
    "with_evidence_viewer_grants",
    "with_evidence_viewer_receipt_signer",
    "with_evidence_viewer_erasure",
    "with_evidence_viewer_checkpoint_store",
    "with_evidence_viewer_compaction_archive",
    "with_evidence_viewer_transparency_publisher",
    "with_soracloud_runtime_mutation_signer",
    "with_global_beacon_partial_signer",
)
EXPECTED_REPEATED_RECORD = (
    "appeal_finance_transaction_signers",
    "Arc<dyniroha_torii::SoraFsAppealFinanceTransactionSigner>",
    "with_appeal_finance_transaction_signer",
    "signer",
    "appeal_finance_transaction_signer_count",
)
EXPECTED_CONSENSUS_SIGNERS = {
    "with_global_beacon_partial_signer": (
        "global_beacon_partial_signer",
        "Arc<dynGlobalBeaconPartialSignerBrokerBackendV1>",
        "signer",
    ),
}
EXPECTED_INVENTORY_SHA256 = (
    "09ad68b7bc1d61fcdc6947def1ade5c06ae7722a41bcbf02e6efdfb1b062f64f"
)
GENERATOR_MACROS = (
    "runtime_provider_backend_collection_v1",
    "runtime_provider_backend_initial_value_v1",
    "append_runtime_provider_backend_debug_field_v1",
    "define_runtime_provider_backend_setter_v1",
    "define_runtime_provider_backends_v1",
)
EXPECTED_GENERATOR_SHA256 = {
    "runtime_provider_backend_collection_v1": (
        "92d72cc8cc4d673cff900df0e37419f9c82ffae164ba8fc037429bf7b7cc7496"
    ),
    "runtime_provider_backend_initial_value_v1": (
        "25666a38d9ca6a94db44c93d6522672c037239bb851ed4b18cd70c419873d10a"
    ),
    "append_runtime_provider_backend_debug_field_v1": (
        "fa5f3be11b2e0c9527875fd971b1b7efae4180c35fa64aea0d39f60c92482e5a"
    ),
    "define_runtime_provider_backend_setter_v1": (
        "e3f801cc46ad8482d68c4b4b7bf57b65f134c59cf5d385f15f99cc48ed831201"
    ),
    "define_runtime_provider_backends_v1": (
        "99c950114546b7781c5b1532d10b6ebc82400638c60b53d7a5f71ac5d8747089"
    ),
}
ENTRY_PATTERN = re.compile(
    r"(?P<docs>(?:        ///[^\n]*\n)+)"
    r"        (?P<kind>optional|repeated) (?P<field>[A-Za-z0-9_]+): "
    r"(?P<backend>[^\n]+?) => (?P<visibility>pub) fn "
    r"(?P<method>with_[A-Za-z0-9_]+)\((?P<argument>[A-Za-z0-9_]+)\)"
    r"(?:, \"(?P<debug_label>[^\"]+)\")?;\n?"
)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _compact(source: str) -> str:
    return "".join(source.split())


def _balanced_braces(source: str, marker: str, offset: int = 0) -> tuple[int, int, str]:
    start = source.index(marker, offset)
    opening = source.index("{", start)
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return start, index + 1, source[opening + 1 : index]
    raise AssertionError(f"unterminated brace block after {marker}")


def _inventory(source: str) -> list[tuple[str, str, str, str, str, str, str, str | None]]:
    _require(
        source.count(INVOCATION_MARKER) == 1,
        "runtime-provider backend inventory must have exactly one invocation",
    )
    _, _, body = _balanced_braces(source, BACKEND_STRUCT_MARKER)
    matches = list(ENTRY_PATTERN.finditer(body))
    residue = ENTRY_PATTERN.sub("", body)
    _require(not residue.strip(), "backend inventory contains unparsed source")
    records = []
    for match in matches:
        docs = "\n".join(
            line.strip() for line in match.group("docs").rstrip("\n").splitlines()
        )
        records.append(
            (
                docs,
                match.group("kind"),
                match.group("field"),
                _compact(match.group("backend")),
                match.group("visibility"),
                match.group("method"),
                match.group("argument"),
                match.group("debug_label"),
            )
        )
    return records


def _inventory_hash(
    records: list[tuple[str, str, str, str, str, str, str, str | None]],
) -> str:
    payload = json.dumps(records, ensure_ascii=False, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def _generator_hashes(source: str) -> dict[str, str]:
    hashes = {}
    for name in GENERATOR_MACROS:
        start, end, _ = _balanced_braces(source, f"macro_rules! {name}")
        hashes[name] = hashlib.sha256(_compact(source[start:end]).encode()).hexdigest()
    return hashes


def _validate_source(source: str) -> None:
    records = _inventory(source)
    _require(len(records) == 55, f"expected 55 frozen backends, found {len(records)}")
    _require(
        len({record[2] for record in records}) == len(records),
        "backend fields must be unique",
    )
    _require(
        len({record[5] for record in records}) == len(records),
        "backend setter methods must be unique",
    )

    optional = [record for record in records if record[1] == "optional"]
    repeated = [record for record in records if record[1] == "repeated"]
    _require(len(optional) == 54, f"expected 54 optional backends, found {len(optional)}")
    _require(len(repeated) == 1, f"expected one repeated backend, found {len(repeated)}")
    _require(
        tuple(record[5] for record in optional) == EXPECTED_OPTIONAL_METHODS,
        "optional backend setter inventory or order changed",
    )
    repeated_record = repeated[0]
    _require(
        (
            repeated_record[2],
            repeated_record[3],
            repeated_record[5],
            repeated_record[6],
            repeated_record[7],
        )
        == EXPECTED_REPEATED_RECORD,
        "the sole repeated appeal-finance signer backend changed",
    )

    optional_by_method = {record[5]: record for record in optional}
    for method, (field, backend, argument) in EXPECTED_CONSENSUS_SIGNERS.items():
        record = optional_by_method.get(method)
        _require(record is not None, f"missing consensus signer setter {method}")
        assert record is not None
        _require(
            (record[2], record[3], record[6]) == (field, backend, argument),
            f"consensus signer setter {method} is mis-mapped",
        )

    inventory_hash = _inventory_hash(records)
    _require(
        inventory_hash == EXPECTED_INVENTORY_SHA256,
        "backend kind, docs, signature, argument, order, or field mapping changed: "
        f"{inventory_hash}",
    )
    generator_hashes = _generator_hashes(source)
    for name, expected_hash in EXPECTED_GENERATOR_SHA256.items():
        actual_hash = generator_hashes[name]
        _require(
            actual_hash == expected_hash,
            f"generator template {name} changed: {actual_hash}",
        )


def _remove_inventory_entry(source: str, method: str) -> str:
    for match in ENTRY_PATTERN.finditer(source):
        if match.group("method") == method:
            return source[: match.start()] + source[match.end() :]
    raise AssertionError(f"missing inventory fixture for {method}")


class RuntimeProviderBrokerBackendSetterSourceTests(unittest.TestCase):
    def test_backend_inventory_and_generator_contract(self) -> None:
        _validate_source(API_PATH.read_text(encoding="utf-8"))

    def test_contract_rejects_source_mutations(self) -> None:
        source = API_PATH.read_text(encoding="utf-8")
        mutations = {
            "retired gateway admission backend": source.replace(
                BACKEND_STRUCT_MARKER,
                BACKEND_STRUCT_MARKER
                + (
                    "\n        /// Attach the deployment-owned stream-token quota, sealed-sequence, and\n"
                    "        /// ordered callback-outbox provider.\n"
                    "        optional stream_token_gateway_admission: "
                    "Arc<dyn iroha_torii::sorafs::StreamTokenGatewayAdmissionProviderV1> "
                    "=> pub fn with_stream_token_gateway_admission(provider);\n"
                ),
                1,
            ),
            "missing entry": _remove_inventory_entry(
                source, "with_bootle_lantern_issuance"
            ),
            "missing beacon signer": _remove_inventory_entry(
                source, "with_global_beacon_partial_signer"
            ),
            "missing independent stream observer": _remove_inventory_entry(
                source, "with_stream_token_state_observer"
            ),
            "observer replaced by signer authority": source.replace(
                "Arc<dyn iroha_torii::sorafs::StreamTokenStateObserverClientV1>",
                "Arc<dyn iroha_torii::sorafs::StreamTokenSignerClientV1>",
                1,
            ),
            "retired stream signer alias": source.replace(
                "with_stream_token_signer_client(client)",
                "with_stream_token_signer(client)",
                1,
            ),
            "mis-mapped field": source.replace(
                "optional bootle_lantern_issuance:",
                "optional privacy_cycle_prf_provider:",
                1,
            ),
            "mis-mapped consensus signer": source.replace(
                "optional global_beacon_partial_signer:",
                "optional soracloud_runtime_mutation_signer:",
                1,
            ),
            "changed rustdoc": source.replace(
                "native Bootle/Lantern issuer", "mutated Bootle/Lantern issuer", 1
            ),
            "changed signature": source.replace(
                "Arc<dyn BootleLanternIssuanceBrokerBackendV1>",
                "Arc<dyn GlobalBeaconPartialSignerBrokerBackendV1>",
                1,
            ),
            "narrowed visibility": source.replace(
                "pub fn $method(mut self", "pub(crate) fn $method(mut self", 1
            ),
            "lost must-use": source.replace(
                "        #[must_use]\n        pub fn $method",
                "        pub fn $method",
                1,
            ),
            "lost optional assignment": source.replace(
                "self.$field = Some($argument);",
                "self.$field = $argument;",
                1,
            ),
            "changed repeated push": source.replace(
                "self.$field.push($argument);",
                "self.$field = vec![$argument];",
                1,
            ),
        }
        for label, mutation in mutations.items():
            with self.subTest(label=label):
                self.assertNotEqual(mutation, source, "mutation fixture must alter source")
                with self.assertRaises((AssertionError, ValueError)):
                    _validate_source(mutation)


if __name__ == "__main__":
    unittest.main()
