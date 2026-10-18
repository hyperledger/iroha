#!/usr/bin/env python3
"""Protect the typed `IrohaRuntimeDeps` setter inventory and its expansion."""

from __future__ import annotations

import hashlib
import json
import re
import unittest
from dataclasses import asdict, dataclass
from pathlib import Path
from unittest.mock import patch

from zk_source_tokens import rust_tokens, token_hash


ROOT = Path(__file__).resolve().parents[2]
SOURCE_PATH = Path("crates/irohad/src/main/runtime_deps.rs")
SOURCE = ROOT / SOURCE_PATH
SETTER_COUNT = 59
INVENTORY_SHA256 = "5217ffd2e8e6236589bea0986633d9a81fa70734e166949fd739c1847b4255aa"
OUTSIDE_PRODUCTION_SHA256 = "594619f97860376fff748dde54821152754d3dd0d6e0c452b4b5f4e2a4e7e156"
MACRO = """macro_rules! define_runtime_dep_setters_v1 {
    (
        $(
            $(#[$attribute:meta])*
            $name:ident($argument:ident: $dependency:ty $(,)?) => $field:ident;
        )+
    ) => {
        $(
            $(#[$attribute])*
            #[must_use]
            pub fn $name(mut self, $argument: $dependency) -> Self {
                self.$field = Some($argument);
                self
            }
        )+
    };
}

"""

NEW_SETTER = re.compile(
    r"(?P<docs>(?:        ///[^\n]*\n)+)"
    r"        (?P<name>with_[A-Za-z0-9_]+)\(\n"
    r"(?P<argument>.*?)"
    r"        \) => (?P<field>[A-Za-z0-9_]+);\n",
    re.DOTALL,
)
ARGUMENT = re.compile(
    r"(?P<indent> +)(?P<name>[A-Za-z0-9_]+): (?P<type>.*),\n",
    re.DOTALL,
)


@dataclass(frozen=True)
class Setter:
    docs: tuple[str, ...]
    name: str
    argument: str
    dependency_type: str
    field: str


def _normal_type(value: str) -> str:
    return " ".join(value.split())


def _new_inventory(source: str) -> tuple[list[Setter], int, int]:
    marker = "    define_runtime_dep_setters_v1! {\n"
    start = source.find(marker)
    if start < 0 or source.count(marker) != 1:
        raise AssertionError("runtime dependency setter invocation is missing or malformed")
    end = source.find("\n    }\n}", start)
    if end < 0:
        raise AssertionError("runtime dependency setter invocation is unterminated")
    end += len("\n    }\n")
    region = source[start:end]
    matches = list(NEW_SETTER.finditer(region))
    if len(matches) != SETTER_COUNT:
        raise AssertionError(f"expected {SETTER_COUNT} typed setter rows, found {len(matches)}")
    body = region.removeprefix(marker).removesuffix("    }\n")
    if NEW_SETTER.sub("", body).strip():
        raise AssertionError("runtime dependency setter inventory contains unparsed source")
    setters = []
    for match in matches:
        argument = ARGUMENT.fullmatch(match.group("argument"))
        if argument is None:
            raise AssertionError(f"malformed typed setter row {match.group('name')}")
        setters.append(
            Setter(
                docs=tuple(line[8:] for line in match.group("docs").splitlines()),
                name=match.group("name"),
                argument=argument.group("name"),
                dependency_type=_normal_type(argument.group("type")),
                field=match.group("field"),
            )
        )
    return setters, start, end


def _production_tokens(source: str) -> tuple[str, ...]:
    """Exclude only explicitly test-gated modules from the production seal."""
    tokens = rust_tokens(source)
    prefix = ("#", "[", "cfg", "(", "test", ")", "]", "mod")
    result = []
    cursor = 0
    while cursor < len(tokens):
        if tokens[cursor : cursor + len(prefix)] != prefix:
            result.append(tokens[cursor])
            cursor += 1
            continue
        opening = cursor + len(prefix) + 1
        if opening >= len(tokens) or tokens[opening] != "{":
            raise AssertionError("test-only module boundary is malformed")
        depth = 1
        cursor = opening + 1
        while cursor < len(tokens) and depth:
            depth += (tokens[cursor] == "{") - (tokens[cursor] == "}")
            cursor += 1
        if depth:
            raise AssertionError("test-only module boundary is unterminated")
    return tuple(result)


def _outside_production_hash(source: str, macro_start: int, start: int, end: int) -> str:
    outside = source[:macro_start] + source[macro_start + len(MACRO) : start] + source[end:]
    return token_hash(" ".join(_production_tokens(outside)))


def _validate_source(source: str) -> None:
    if source.count("macro_rules! define_runtime_dep_setters_v1") != 1:
        raise AssertionError("setter emitter count changed")
    macro_start = source.index("macro_rules! define_runtime_dep_setters_v1")
    if source[macro_start : macro_start + len(MACRO)] != MACRO:
        raise AssertionError("setter emitter body changed")
    rows, start, end = _new_inventory(source)
    forbidden = ("dyn Fn", "FnMut", "FnOnce", "Action", "Scenario", "$body", "$setup")
    if any(token in source[macro_start:] for token in forbidden):
        raise AssertionError("callback or body-dispatch escape hatch introduced")
    if len({row.name for row in rows}) != len(rows):
        raise AssertionError("duplicate public setter name")
    if len({row.field for row in rows}) != len(rows):
        raise AssertionError("duplicate runtime dependency field mapping")
    inventory = json.dumps([asdict(row) for row in rows], ensure_ascii=False,
                           separators=(",", ":")).encode()
    if hashlib.sha256(inventory).hexdigest() != INVENTORY_SHA256:
        raise AssertionError("typed setter docs, order, name, argument, type or field changed")
    if _outside_production_hash(source, macro_start, start, end) != OUTSIDE_PRODUCTION_SHA256:
        raise AssertionError("production outside the setter family changed")


class RuntimeDepsSetterSourceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SOURCE.read_text(encoding="utf-8")

    def test_current_typed_inventory_and_expansion_are_exact(self) -> None:
        with patch("subprocess.check_output", side_effect=AssertionError("mutable Git input")):
            _validate_source(self.source)

    def test_mutated_method_name_is_rejected(self) -> None:
        changed = self.source.replace(
            "with_privacy_release_anchor(", "with_privacy_release_head(", 1
        )
        with self.assertRaises(AssertionError):
            _validate_source(changed)

    def test_mutated_field_mapping_is_rejected(self) -> None:
        changed = self.source.replace(
            ") => privacy_release_anchor;",
            ") => transparency_leader_lease_provider;",
            1,
        )
        with self.assertRaises(AssertionError):
            _validate_source(changed)

    def test_mutated_dependency_type_is_rejected(self) -> None:
        changed = self.source.replace(
            "ProductionPrivacyReleaseAnchorV1", "ProductionPrivacyCyclePrfProviderV1", 1
        )
        with self.assertRaises(AssertionError):
            _validate_source(changed)

    def test_callback_escape_hatch_is_rejected(self) -> None:
        changed = self.source.replace(
            "    define_runtime_dep_setters_v1! {",
            "    // dyn Fn callback\n    define_runtime_dep_setters_v1! {",
            1,
        )
        with self.assertRaises(AssertionError):
            _validate_source(changed)

    def test_emitter_mutation_is_rejected(self) -> None:
        changed = self.source.replace("self.$field = Some($argument);", "self.$field = None;", 1)
        with self.assertRaises(AssertionError):
            _validate_source(changed)

    def test_every_new_custody_owner_is_mandatory(self) -> None:
        methods = (
            "with_sumeragi_global_beacon_partial_signer",
            "with_sorafs_stream_token_signer_client",
            "with_sorafs_stream_token_state_observer",
            "with_sorafs_stream_token_approved_anchor",
        )
        for method in methods:
            with self.subTest(method=method):
                matches = [row for row in NEW_SETTER.finditer(self.source)
                           if row.group("name") == method]
                self.assertEqual(len(matches), 1)
                match = matches[0]
                changed = self.source[:match.start()] + self.source[match.end():]
                with self.assertRaises(AssertionError):
                    _validate_source(changed)

    def test_retired_mint_finality_dependency_is_absent(self) -> None:
        self.assertNotIn("kagemusha_mint_finality_authority", self.source)
        self.assertNotIn("KagemushaMintFinalityLocalAuthorityV1", self.source)

    def test_production_outside_the_family_is_sealed(self) -> None:
        for old, new in (
            ("self.sumeragi_assert_fresh_key = asserted;",
             "self.sumeragi_assert_fresh_key = true;"),
            ('"active global-beacon key session is absent"',
             '"active global-beacon key session is present"'),
            ("#[cfg(test)]", "#[cfg(not(test))]"),
        ):
            with self.subTest(old=old):
                self.assertIn(old, self.source)
                with self.assertRaisesRegex(AssertionError, "outside the setter family"):
                    _validate_source(self.source.replace(old, new, 1))

    def test_unparsed_invocation_body_is_rejected(self) -> None:
        marker = "    define_runtime_dep_setters_v1! {\n"
        changed = self.source.replace(marker, marker + "        unowned();\n", 1)
        with self.assertRaisesRegex(AssertionError, "unparsed source"):
            _validate_source(changed)

    def test_setter_family_whitespace_growth_preserves_contract(self) -> None:
        marker = "    define_runtime_dep_setters_v1! {\n"
        self.assertEqual(self.source.count(marker), 1)
        changed = self.source.replace(marker, marker + "\n" * 20_000, 1)
        _validate_source(changed)


if __name__ == "__main__":
    unittest.main()
