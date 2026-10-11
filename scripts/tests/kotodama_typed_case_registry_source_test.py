#!/usr/bin/env python3
"""Check the typed Kotodama registry fixtures, case inventories and semantics."""

from __future__ import annotations

import hashlib
import json
import re
import unittest
from pathlib import Path

if __package__:
    from .zk_source_tokens import token_hash
else:
    from zk_source_tokens import token_hash


ROOT = Path(__file__).resolve().parents[2]
IVM_SOURCE = Path("crates/ivm/tests/kotodama.rs")
IR_SOURCE = Path("crates/kotodama_lang/src/ir.rs")
FIXTURE_MANIFEST = Path("crates/kotodama_lang/kotodama_fixtures_v1.manifest.json")

IVM_REGION_SHA256 = "81e841a583ba2ac9e7968aed426b6b09e65bb80a699342b40225943fa37ddfdf"
IR_REGION_SHA256 = "41562e7743c639e665fb3674538986ac99ab1d91691c41c7966e596d91b7aadc"
IVM_CODE_SHA256 = "d6e75fc454eed1e51a73c77bbf840ad9e4a6d78419324db8b7f5616f40353bf1"
IR_CODE_SHA256 = "7b089765de4004f3e2634ee9807324377348e7aec831d401bf7c3e927ee5ad5a"
REGISTRY_FIXTURES = ROOT / "fixtures/documentation/kotodama-registry"
IVM_CASE_IDS_SHA256 = "9c2a8f00d546b43ea86589639998900a540961bdc6b4b4b9b4a6e2b4ce1c92cc"

IVM_MACROS = (
    ("compile_cases", 9),
    ("compile_rejection_cases", 32),
    ("semantic_rejection_cases", 27),
    ("vm_result_cases", 8),
    ("parse_rejection_cases", 5),
    ("semantic_success_cases", 7),
)
IVM_REGISTRY_TESTS = (
    "compile_case_registry",
    "compile_rejection_case_registry",
    "semantic_rejection_case_registry",
    "vm_result_case_registry",
    "parse_rejection_case_registry",
    "semantic_success_case_registry",
)
IR_TEST_NAMES = (
    "lower_resolve_account_alias_builtin",
    "lower_resolve_account_alias_builtin_uses_string_literal",
    "lower_resolve_account_alias_invalid_literal_uses_string_literal",
    "lower_resolve_account_alias_domain_qualified_builtin_uses_string_literal",
    "lower_resolve_account_alias_invalid_domain_qualified_literal_uses_string_literal",
    "lower_account_id_alias_literal_to_resolve_account_alias",
    "lower_account_id_domain_qualified_alias_literal_to_resolve_account_alias",
    "account_id_invalid_non_alias_literal_is_rejected_before_lowering",
    "lower_account_id_canonical_literal_to_static_account_dataref",
    "lower_account_id_invalid_alias_shaped_literal_to_resolve_account_alias",
    "lower_account_id_invalid_domain_qualified_alias_literal_to_resolve_account_alias",
)


def _read_source(relative: Path) -> str:
    path = ROOT / relative
    if path.is_symlink() or not path.is_file():
        raise AssertionError(f"missing or non-regular source: {relative}")
    path.resolve(strict=True).relative_to(ROOT)
    return path.read_text(encoding="utf-8")


def _region(source: str, start: str, end: str) -> str:
    start_index = source.index(start)
    end_index = source.index(end, start_index)
    return source[start_index:end_index]


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


class KotodamaTypedCaseRegistrySourceTest(unittest.TestCase):
    """Authenticate the data-only registries, case inventories and assertions."""

    def _assert_registry_contract(self, ivm_source: str, ir_source: str) -> None:
        ivm_region = _region(
            ivm_source,
            "#[derive(Clone, Copy)]\nenum CaseSource",
            "#[test]\nfn many_string_literals_load_under_wide_guard",
        )
        ir_region = _region(
            ir_source,
            "    #[derive(Clone, Copy)]\n    enum AliasSource",
            "    #[test]\n    fn lower_get_quantity_builtin",
        )

        self.assertEqual(token_hash(ivm_region), IVM_CODE_SHA256)
        self.assertEqual(token_hash(ir_region), IR_CODE_SHA256)

        forbidden = (
            "rustfmt::skip",
            ":tt",
            "$body",
            "$action",
            "$step",
            "dyn Fn",
            "impl Fn",
            "kotodama_integration_v1",
        )
        for token in forbidden:
            self.assertNotIn(token, ivm_region)
            self.assertNotIn(token, ir_region)

        case_ids: list[str] = []
        for macro_name, expected_count in IVM_MACROS:
            self.assertEqual(ivm_region.count(f"macro_rules! {macro_name}"), 1)
            invocation_start = ivm_region.index(f"{macro_name}! {{")
            invocation_end = ivm_region.index("\n}", invocation_start)
            invocation = ivm_region[invocation_start:invocation_end]
            ids = re.findall(r'^ {4}"([^"]+)"', invocation, re.MULTILINE)
            self.assertEqual(len(ids), expected_count, macro_name)
            case_ids.extend(ids)

        self.assertEqual(len(case_ids), 88)
        self.assertEqual(len(set(case_ids)), 88)
        self.assertEqual(len({case_id.split("/", 1)[0] for case_id in case_ids}), 74)
        self.assertEqual(
            hashlib.sha256(
                json.dumps(case_ids, separators=(",", ":")).encode()
            ).hexdigest(),
            IVM_CASE_IDS_SHA256,
        )
        for test_name in IVM_REGISTRY_TESTS:
            self.assertIn(f"#[test]\nfn {test_name}()", ivm_region)
        self.assertEqual(ivm_region.count("#[test]"), len(IVM_REGISTRY_TESTS))

        emitted_names = tuple(
            re.findall(r"(?m)^    alias_lowering_case!\(\n        ([a-z0-9_]+),", ir_region)
        )
        self.assertEqual(emitted_names, tuple(name for name in IR_TEST_NAMES if name != "account_id_invalid_non_alias_literal_is_rejected_before_lowering"))
        self.assertEqual(len(set(emitted_names)), len(IR_TEST_NAMES) - 1)
        self.assertEqual(ir_region.count("macro_rules! alias_lowering_case"), 1)
        self.assertEqual(ir_region.count("#[test]"), 2)
        self.assertIn("fn account_id_invalid_non_alias_literal_is_rejected_before_lowering()", ir_region)
        self.assertIn('assert_eq!(error.code, "E_INVALID_ID_LITERAL");', ir_region)

        manifest = json.loads(_read_source(FIXTURE_MANIFEST))
        source_entry = next(
            entry
            for entry in manifest["source_files"]
            if entry["path"] == IR_SOURCE.as_posix()
        )
        manifest_names = tuple(source_entry["test_names"])
        first = manifest_names.index(IR_TEST_NAMES[0])
        self.assertEqual(manifest_names[first : first + len(IR_TEST_NAMES)], IR_TEST_NAMES)

    def test_typed_case_registry_contract(self) -> None:
        self._assert_registry_contract(_read_source(IVM_SOURCE), _read_source(IR_SOURCE))

    def test_registry_fixture_bytes_authenticate_current_semantic_seals(self) -> None:
        for name, byte_digest, code_digest in (
            ("kotodama-ivm-registry-region.txt", IVM_REGION_SHA256, IVM_CODE_SHA256),
            ("kotodama-ir-registry-region.txt", IR_REGION_SHA256, IR_CODE_SHA256),
        ):
            with self.subTest(name=name):
                region = (REGISTRY_FIXTURES / name).read_text(encoding="utf-8")
                self.assertEqual(_sha256(region), byte_digest)
                self.assertEqual(token_hash(region), code_digest)

    def test_registry_whitespace_growth_preserves_semantic_contract(self) -> None:
        ivm_source = _read_source(IVM_SOURCE)
        ir_source = _read_source(IR_SOURCE)
        ivm_end = "#[test]\nfn many_string_literals_load_under_wide_guard"
        ir_end = "    #[test]\n    fn lower_get_quantity_builtin"
        self.assertEqual(ivm_source.count(ivm_end), 1)
        self.assertEqual(ir_source.count(ir_end), 1)
        self._assert_registry_contract(
            ivm_source.replace(ivm_end, "\n" * 20_000 + ivm_end, 1),
            ir_source.replace(ir_end, "\n" * 20_000 + ir_end, 1),
        )

    def test_registry_semantic_mutation_is_rejected(self) -> None:
        ivm_source = _read_source(IVM_SOURCE)
        ir_source = _read_source(IR_SOURCE)
        self.assertIn("Self::Exact(source) => source,", ivm_source)
        changed = ivm_source.replace("Self::Exact(source) => source,", 'Self::Exact(source) => "",', 1)
        with self.assertRaises(AssertionError):
            self._assert_registry_contract(changed, ir_source)


if __name__ == "__main__":
    unittest.main()
