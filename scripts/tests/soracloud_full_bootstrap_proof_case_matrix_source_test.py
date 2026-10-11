#!/usr/bin/env python3
"""Protect Soracloud's typed full-bootstrap proof-validation test matrices."""

from __future__ import annotations

import hashlib
import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_PATH = REPO_ROOT / "crates/iroha_core/src/smartcontracts/isi/soracloud_tests.rs"

REGIONS = {
    "verifier_record": (
        '#[derive(Clone, Copy)]\nenum FullBootstrapVerifierRecordMetadataTamper',
        '#[cfg(feature = "zk-stark")]\n#[test]\nfn soracloud_fhe_full_bootstrap_execution_proof_helper_rejects_empty_input_slots',
        "e6561ab6eedd4281ead704f6895e6e467b324fd4a0abc9bc02354a9e1c25f63a",
    ),
    "release_verifier": (
        '#[cfg(feature = "zk-stark")]\n#[derive(Clone, Copy)]\nenum FullBootstrapReleaseVerifierCase',
        '#[cfg(feature = "zk-stark")]\n#[test]\nfn soracloud_fhe_full_bootstrap_execution_release_prover_rejects_role_spliced_artifacts',
        "c85150accfdc635efc52d572f5a1ce5f80983c038d54dd9ad5528fd98ea5e449",
    ),
    "guarded_verifier": (
        '#[cfg(all(feature = "zk-stark", feature = "zk-preverify"))]\n#[derive(Clone, Copy)]\nenum FullBootstrapGuardedVerifierCase',
        '#[cfg(feature = "zk-preverify")]\n#[test]\nfn soracloud_fhe_full_bootstrap_execution_guarded_verifier_rejects_invalid_native_air',
        "58c09a27c28904d140cbcdc9fe77e8650511ff81073ffc5cb2e5945272dc62ed",
    ),
    "proof_quota": (
        '#[cfg(feature = "zk-stark")]\nfn enable_full_bootstrap_proof_quotas<P>(',
        'fn sample_fhe_input_admission_proof(\n',
        "8b92df900659acde31121bc880561db9facd826bed909341eec9170a7144c167",
    ),
}

VERIFIER_CASES = {
    "soracloud_fhe_full_bootstrap_execution_proof_requires_governed_verifier_record": "MissingRecord",
    "soracloud_fhe_full_bootstrap_execution_proof_rejects_inactive_governed_verifier_record": "InactiveRecord",
    "soracloud_fhe_full_bootstrap_execution_proof_rejects_out_of_window_governed_verifier_record": "OutsideHeightWindow",
    "soracloud_fhe_full_bootstrap_execution_proof_rejects_unverified_fake_proof": "FakeProof",
}

DIRECT_TESTS = {
    "soracloud_fhe_full_bootstrap_execution_proof_rejects_verifier_record_metadata_drift": (
        "test",
        "allow(clippy::too_many_lines)",
    ),
}

NAMED_CASES = {
    "soracloud_fhe_full_bootstrap_execution_proof_rejects_generic_binding_air_active_verifier": (
        ("cfg(feature = \"zk-stark\")", "test"),
        "GenericBindingAir",
    ),
    "soracloud_fhe_full_bootstrap_execution_proof_accepts_release_prover_native_air_active_verifier": (
        ("cfg(feature = \"zk-stark\")", "test"),
        "AcceptNativeAir",
    ),
    "soracloud_fhe_full_bootstrap_execution_proof_rejects_release_prover_trace_root_drift": (
        ("cfg(feature = \"zk-stark\")", "test"),
        "TraceRootDrift",
    ),
    "soracloud_fhe_full_bootstrap_execution_proof_rejects_release_prover_root_drift": (
        ("cfg(feature = \"zk-stark\")", "test"),
        "RootDrift",
    ),
    "soracloud_fhe_full_bootstrap_execution_proof_rejects_release_prover_opened_air_drift": (
        ("cfg(feature = \"zk-stark\")", "test"),
        "OpenedAirDrift",
    ),
    "soracloud_fhe_full_bootstrap_execution_proof_rejects_release_prover_opening_commitment_drift": (
        ("cfg(feature = \"zk-stark\")", "test"),
        "OpeningCommitmentDrift",
    ),
    "soracloud_fhe_full_bootstrap_execution_proof_rejects_generic_air_drift": (
        ("cfg(feature = \"zk-stark\")", "test"),
        "GenericAirDrift",
    ),
    "soracloud_fhe_full_bootstrap_execution_guarded_verifier_rejects_release_native_air_drift": (
        (
            "cfg(all(feature = \"zk-stark\", feature = \"zk-preverify\"))",
            "test",
            "allow(clippy::too_many_lines)",
        ),
        "ReleaseNativeAir",
    ),
    "soracloud_fhe_full_bootstrap_execution_guarded_verifier_rejects_release_native_air_root_drift": (
        (
            "cfg(all(feature = \"zk-stark\", feature = \"zk-preverify\"))",
            "test",
            "allow(clippy::too_many_lines)",
        ),
        "ReleaseNativeAirRoot",
    ),
    "soracloud_fhe_full_bootstrap_execution_guarded_verifier_rejects_release_native_air_opening_commitment_drift": (
        (
            "cfg(all(feature = \"zk-stark\", feature = \"zk-preverify\"))",
            "test",
            "allow(clippy::too_many_lines)",
        ),
        "ReleaseNativeAirOpeningCommitment",
    ),
    "soracloud_fhe_full_bootstrap_execution_guarded_verifier_rejects_generic_air_drift": (
        (
            "cfg(all(feature = \"zk-stark\", feature = \"zk-preverify\"))",
            "test",
            "allow(clippy::too_many_lines)",
        ),
        "GenericAir",
    ),
}

METADATA_CASES = (
    ("Namespace", "soracloud namespace"),
    ("Backend", "must use STARK backend"),
    ("Curve", "goldilocks STARK field"),
    ("PublicInputs", "public-input schema mismatch"),
    ("CircuitId", "canonical v1 circuit"),
    ("Version", "canonical v1 circuit version"),
    ("GasSchedule", "gas_schedule_id mismatch"),
    ("InactiveCircuitMapping", "circuit/version not active"),
    ("MaxProofBytes", "max_proof_bytes"),
    ("MissingKey", "verifying key bytes missing"),
    ("VkLen", "vk_len mismatch"),
    ("Commitment", "commitment must match governed artifact"),
    ("KeyBytes", "bytes must match governed artifact"),
)

REQUIRED_TOKENS = {
    "verifier_record": (
        "status = ConfidentialStatus::Withdrawn",
        ".activation_height = Some(activation_height)",
        '"out-of-window full-bootstrap execution verifier must fail closed"',
        "verifying_keys_by_circuit.remove",
        'record.namespace = "other".to_string()',
        "record.backend = BackendTag::NativePipaRPasta",
        'record.curve = "bn254".to_string()',
        "record.public_inputs_schema_hash = [0xA7; Hash::LENGTH]",
        '"soracloud_fhe_full_bootstrap_execution_v2".to_string()',
        "SORACLOUD_FHE_FULL_BOOTSTRAP_EXECUTION_PROOF_VERSION_V1",
        'Some("wrong_full_bootstrap_execution_gas".to_string())',
        "record.max_proof_bytes = 1",
        "record.key = None",
        ".saturating_add(1)",
        "record.commitment = [0xA8; Hash::LENGTH]",
        "drifted_key.bytes.push(0xA9)",
        'assert_invariant_contains(err, "verifying key not found")',
        'assert_invariant_contains(err, "verifying key is not active")',
        "assert_invalid_parameter_contains(err, expected_error)",
        'assert_invalid_parameter_contains(err, "native AIR envelope")',
        'assert_invalid_parameter_contains(err, "requires the zk-stark feature")',
    ),
    "release_verifier": (
        "sample_full_bootstrap_execution_binding_air_proofs_for_claims",
        "prove_soracloud_fhe_full_bootstrap_execution_proofs_for_claims_v1",
        "mutate_native_stark_digest(trace_root)",
        "native_stark_test_digest(0xCD)",
        "native_stark_test_digest(0xCE)",
        ".composition_value = 1",
        "execution_native_air_replay_tamper_cases()",
        "apply_execution_native_air_replay_tamper(native, tamper)",
        "native_air_tamper_cases()",
        "full_bootstrap_generic_air_tamper_error(tamper, expected_error)",
        "enable_full_bootstrap_proof_quotas",
        '"trace root does not match governed arithmetic trace"',
        '"composition root does not match governed AIR evaluation"',
        '"FRI query Merkle root mismatch"',
        '"composition value does not match governed AIR evaluation"',
        "FHE_FULL_BOOTSTRAP_GENERIC_BINDING_AIR_REJECTED",
        ".expect_err(failure_context)",
        "assert_invalid_parameter_contains(err, expected_error)",
    ),
    "guarded_verifier": (
        "stx.apply()",
        "let mut stx = state_block.transaction()",
        "native_air_tamper_cases()",
        "execution_native_air_replay_tamper_cases()",
        "apply_native_air_tamper(native, tamper)",
        "apply_execution_native_air_replay_tamper(native, tamper)",
        "native_stark_test_digest(0xCF)",
        "native_stark_test_digest(0xD0)",
        "full_bootstrap_bfv_native_air_tamper_error(tamper)",
        "full_bootstrap_generic_air_tamper_error(tamper, expected_error)",
        '"guarded verifier must reject release-native BFV AIR drift"',
        '"guarded verifier must reject release-native composition-root drift"',
        '"guarded verifier must reject release-native FRI base-root drift"',
        '"guarded verifier must reject release-native opening commitment drift"',
        '"guarded verifier must reject full-bootstrap execution generic AIR drift"',
        ".expect_err(failure_context)",
        "assert_invalid_parameter_contains(err, expected_error)",
    ),
    "proof_quota": (
        "impl IntoIterator<Item = P>",
        "P: std::borrow::Borrow<SoracloudFheFullBootstrapExecutionProofV1>",
        ".into_iter()",
        ".map(|proof| proof.borrow().proof.proof.bytes.len())",
        "enable_stark_sample_proof_quotas(state_transaction, &lengths)",
    ),
}

FORBIDDEN_RUNNER_TOKENS = (
    "Box<dyn Fn",
    "Box<dyn FnMut",
    "callback:",
    "custom_case:",
    "escape_hatch",
)


class GuardError(AssertionError):
    """Raised when the protected full-bootstrap source contract changes."""


def _normalized_hash(source: str) -> str:
    return hashlib.sha256(re.sub(r"\s+", "", source).encode()).hexdigest()


def _region(source: str, label: str) -> str:
    start_marker, end_marker, _expected_hash = REGIONS[label]
    if source.count(start_marker) != 1 or source.count(end_marker) != 1:
        raise GuardError(f"{label}: region markers must occur exactly once")
    start = source.index(start_marker)
    end = source.index(end_marker, start)
    return source[start:end]


def _attributes(attribute_source: str) -> tuple[str, ...]:
    return tuple(re.findall(r"#\[([^\]\n]+)\]", attribute_source))


def _direct_attributes(source: str, test_name: str) -> tuple[str, ...]:
    pattern = re.compile(
        rf"(?P<attrs>(?:#\[[^\]\n]+\]\n)+)"
        rf"fn\s+{re.escape(test_name)}\s*\(",
    )
    matches = list(pattern.finditer(source))
    if len(matches) != 1:
        raise GuardError(f"{test_name}: expected one direct test definition")
    return _attributes(matches[0].group("attrs"))


def _named_case(region: str, test_name: str) -> tuple[tuple[str, ...], str]:
    pattern = re.compile(
        rf"(?P<attrs>(?:    #\[[^\]\n]+\]\n)+)"
        rf"    {re.escape(test_name)}\s*=>\s*(?P<case>[A-Za-z0-9_]+);"
    )
    matches = list(pattern.finditer(region))
    if len(matches) != 1:
        raise GuardError(f"{test_name}: expected one named typed-case row")
    match = matches[0]
    return _attributes(match.group("attrs")), match.group("case")


def validate_module_owner(owner: str) -> None:
    pattern = r'#\[cfg\(test\)\]\s*mod tests\s*\{\s*use iroha_model_base::domain::DomainId;\s*use iroha_model_base::peer::PeerId;\s*include!\("soracloud_tests.rs"\);\s*mod agent_apartment;\s*\}'
    if len(re.findall(pattern, owner)) != 1 or owner.count('include!("soracloud_tests.rs")') != 1:
        raise GuardError("Soracloud current test leaf lost its compiled cfg(test) owner")


def validate_source(source: str) -> None:
    regions = {label: _region(source, label) for label in REGIONS}
    all_names = set(VERIFIER_CASES) | set(DIRECT_TESTS) | set(NAMED_CASES)
    for test_name in all_names:
        occurrences = len(re.findall(rf"\b{re.escape(test_name)}\b", source))
        if occurrences != 1:
            raise GuardError(f"{test_name}: expected one source occurrence, found {occurrences}")

    verifier_region = regions["verifier_record"]
    macro_contract = '                #[test]\n                fn $name() -> Result<(), eyre::Report> {'
    if macro_contract not in verifier_region:
        raise GuardError("verifier-record macro no longer emits the exact test attribute")
    for test_name, expected_case in VERIFIER_CASES.items():
        pattern = re.compile(
            rf"\b{re.escape(test_name)}\s*=>\s*{re.escape(expected_case)}\s*,"
        )
        if len(pattern.findall(verifier_region)) != 1:
            raise GuardError(f"{test_name}: verifier-record case wiring changed")
    for test_name, expected_attributes in DIRECT_TESTS.items():
        attributes = _direct_attributes(verifier_region, test_name)
        if attributes != expected_attributes:
            raise GuardError(
                f"{test_name}: attributes {attributes} != {expected_attributes}"
            )
    for variant, expected_error in METADATA_CASES:
        pair = re.compile(
            rf"FullBootstrapVerifierRecordMetadataTamper::{variant}\s*,\s*"
            rf'"{re.escape(expected_error)}"'
        )
        if len(pair.findall(verifier_region)) != 1:
            raise GuardError(f"{variant}: metadata error mapping changed")

    for test_name, (expected_attributes, expected_case) in NAMED_CASES.items():
        label = "guarded_verifier" if "guarded_verifier" in test_name else "release_verifier"
        attributes, case = _named_case(regions[label], test_name)
        if attributes != expected_attributes:
            raise GuardError(
                f"{test_name}: attributes {attributes} != {expected_attributes}"
            )
        if case != expected_case:
            raise GuardError(f"{test_name}: case {case} != {expected_case}")

    for label, tokens in REQUIRED_TOKENS.items():
        for token in tokens:
            if token not in regions[label]:
                raise GuardError(f"{label}: missing semantic token {token!r}")
    protected_runners = "".join(
        regions[label] for label in ("verifier_record", "release_verifier", "guarded_verifier")
    )
    for token in FORBIDDEN_RUNNER_TOKENS:
        if token in protected_runners:
            raise GuardError(f"typed runners contain forbidden escape hatch {token!r}")
    for label, region in regions.items():
        expected_hash = REGIONS[label][2]
        observed_hash = _normalized_hash(region)
        if observed_hash != expected_hash:
            raise GuardError(f"{label}: semantic hash changed: {observed_hash}")


def _replace_once(source: str, old: str, new: str) -> str:
    if source.count(old) != 1:
        raise AssertionError(f"mutation preimage must occur once: {old!r}")
    return source.replace(old, new, 1)


def _replace_in_region(source: str, label: str, old: str, new: str) -> str:
    region = _region(source, label)
    if region.count(old) != 1:
        raise AssertionError(f"{label}: mutation preimage must occur once: {old!r}")
    return source.replace(region, region.replace(old, new, 1), 1)


class SoracloudFullBootstrapProofCaseMatrixSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SOURCE_PATH.read_text()

    def assert_rejected(self, mutated: str) -> None:
        with self.assertRaises(GuardError):
            validate_source(mutated)

    def test_current_module_owner_and_redirect_controls(self) -> None:
        owner = (REPO_ROOT / "crates/iroha_core/src/smartcontracts/isi/soracloud.rs").read_text()
        validate_module_owner(owner)
        for old, new in (
            ('include!("soracloud_tests.rs")', 'include!("uncompiled_tests.rs")'),
            ('#[cfg(test)]\nmod tests', '#[cfg(any())]\nmod tests'),
        ):
            self.assertEqual(owner.count(old), 1)
            with self.subTest(target=old), self.assertRaises(GuardError):
                validate_module_owner(owner.replace(old, new, 1))

    def test_current_source_preserves_case_matrices(self) -> None:
        validate_source(self.source)

    def test_name_mutation_is_rejected(self) -> None:
        name = next(iter(VERIFIER_CASES))
        self.assert_rejected(_replace_once(self.source, name, f"{name}_mutated"))

    def test_ordered_attribute_mutation_is_rejected(self) -> None:
        name = next(iter(NAMED_CASES))
        old = f'#[cfg(feature = "zk-stark")]\n    #[test]\n    {name}'
        self.assert_rejected(_replace_once(self.source, old, old.replace("#[test]", "#[ignore]")))

    def test_case_wiring_mutation_is_rejected(self) -> None:
        name = next(iter(NAMED_CASES))
        old = f"{name} => GenericBindingAir;"
        self.assert_rejected(_replace_once(self.source, old, old.replace("GenericBindingAir", "RootDrift")))

    def test_metadata_adversary_mutation_is_rejected(self) -> None:
        old = "record.commitment = [0xA8; Hash::LENGTH]"
        self.assert_rejected(_replace_once(self.source, old, old.replace("0xA8", "0xAA")))

    def test_release_root_mutation_is_rejected(self) -> None:
        old = "native_stark_test_digest(0xCD)"
        self.assert_rejected(_replace_once(self.source, old, "native_stark_test_digest(0xCC)"))

    def test_guarded_root_mutation_is_rejected(self) -> None:
        old = "native_stark_test_digest(0xD0)"
        self.assert_rejected(_replace_once(self.source, old, "native_stark_test_digest(0xD1)"))

    def test_error_category_mutation_is_rejected(self) -> None:
        old = "assert_invalid_parameter_contains(err, expected_error)"
        mutated = _replace_in_region(
            self.source,
            "release_verifier",
            old,
            "assert_invariant_contains(err, expected_error)",
        )
        self.assert_rejected(mutated)

    def test_quota_helper_mutation_is_rejected(self) -> None:
        old = ".map(|proof| proof.borrow().proof.proof.bytes.len())"
        mutated = _replace_in_region(
            self.source,
            "proof_quota",
            old,
            ".map(|proof| proof.borrow().proof.proof.bytes.len().saturating_sub(1))",
        )
        self.assert_rejected(mutated)

    def test_callback_escape_hatch_is_rejected(self) -> None:
        old = '    GenericBindingAir,'
        mutated = _replace_in_region(
            self.source,
            "release_verifier",
            old,
            old + '\n    Custom(Box<dyn Fn()>),',
        )
        self.assert_rejected(mutated)

    def test_whitespace_growth_preserves_case_matrices(self) -> None:
        validate_source(self.source + "\n" * 100_000)


if __name__ == "__main__":
    unittest.main()
