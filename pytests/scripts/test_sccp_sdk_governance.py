"""Keep SDK governance envelopes aligned with the current Norito model.

Run from a checkout with ``python3 -m pytest -q
pytests/scripts/test_sccp_sdk_governance.py``. No compiler, network or signing
inputs are needed. These source checks prevent separately maintained SDK tag
lists from drifting; Swift/Kotlin runtime tests still own decoder behavior.
"""

from pathlib import Path
import re

import pytest


ROOT = Path(__file__).resolve().parents[2]
SDK_PATHS = {
    "swift": "IrohaSwift/Sources/IrohaSwift/ToriiGovernanceProposalKinds.swift",
    "kotlin": "kotlin/core-jvm/src/main/java/org/hyperledger/iroha/sdk/client/ParliamentProposalValidatorV1.kt",
}


def _model_variants(name: str) -> dict[str, str | None]:
    source = (ROOT / "crates/iroha_data_model/src/sccp/governance.rs").read_text()
    marker = f"pub enum {name} {{\n"
    assert source.count(marker) == 1
    body = source.split(marker, 1)[1].split("\n}", 1)[0]
    body = re.sub(r"^\s*//[^\n]*", "", body, flags=re.MULTILINE)
    variant = re.compile(
        r'\s*#\[codec\(index = \d+\)\]\s*'
        r'#\[norito\(rename = "([a-z_]+)"\)\]\s*'
        r'([A-Za-z0-9_]+)(?:\(([A-Za-z0-9_]+)\))?,'
    )
    rows = variant.findall(body)
    assert rows and not variant.sub("", body).strip(), "review changed Norito enum syntax"
    assert len({tag for tag, _, _ in rows}) == len(rows), "duplicate wire tag"
    assert len({rust_name for _, rust_name, _ in rows}) == len(rows), "duplicate variant"
    return {tag: payload or None for tag, _, payload in rows}


def _tags(literals: str) -> set[str]:
    tags = re.findall(r'"([a-z_]+)"', literals)
    assert tags and len(tags) == len(set(tags)), "empty or duplicate SDK tags"
    assert not re.sub(r'"[a-z_]+"|[\s,]', "", literals), "review changed SDK tag syntax"
    return set(tags)


@pytest.mark.parametrize("language", SDK_PATHS)
def test_action_tags_match_current_norito_model(language: str) -> None:
    source = (ROOT / SDK_PATHS[language]).read_text()
    pattern = (
        r"private static let actionTags: Set<String> = \[(.*?)\n    \]"
        if language == "swift"
        else r"private val SCCP_GOVERNANCE_ACTIONS = setOf\((.*?)\n    \)"
    )
    lists = re.findall(pattern, source, re.DOTALL)
    assert len(lists) == 1
    expected = set(_model_variants("SccpGovernanceActionV1"))
    actual = _tags(lists[0])
    assert actual == expected, (language, "missing", expected - actual, "retired", actual - expected)


@pytest.mark.parametrize("language", SDK_PATHS)
def test_subject_tags_and_coordinate_owners_match_current_norito_model(language: str) -> None:
    source = (ROOT / SDK_PATHS[language]).read_text()
    variants = _model_variants("SccpGovernanceSubjectV1")
    assert set(variants.values()) == {None, "SccpNetworkV1"}, "review new subject coordinate type"
    expected_network = {tag for tag, payload in variants.items() if payload == "SccpNetworkV1"}
    expected_null = {tag for tag, payload in variants.items() if payload is None}
    if language == "swift":
        body = source.split("private static func validateSubject(", 1)[1].split("\n        default:", 1)[0]
        network = re.findall(r"case ([^:\n]+):\s+let key = try exactObject\(", body)
        null = re.findall(r'case ("[a-z_]+"):.*?guard case \.null\? = subject\["key"\]', body, re.DOTALL)
        all_cases = re.findall(r"^\s*case ([^:\n]+):", body, re.MULTILINE)
    else:
        body = source.split("private fun sccpGovernanceSubject(", 1)[1].split("private fun sccpExternalNetwork(", 1)[0]
        network = re.findall(r'((?:"[a-z_]+"[\s,]*)+)->\s*sccpExternalNetwork\(', body)
        null = re.findall(r'("[a-z_]+") -> require\(value\["key"\] == null\)', body)
        all_cases = re.findall(r'^\s*((?:"[a-z_]+"[\s,]*)+)->', body, re.MULTILINE)
    assert len(network) == 1 and len(null) == len(expected_null)
    assert _tags(network[0]) == expected_network, (language, "network subjects")
    assert _tags(",".join(null)) == expected_null, (language, "null subjects")
    assert _tags(",".join(all_cases)) == set(variants), (language, "closed subjects")
