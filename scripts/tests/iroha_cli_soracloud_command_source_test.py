#!/usr/bin/env python3
"""Protect the typed SoraCloud CLI command corridor and its test contracts."""

from __future__ import annotations

import hashlib
import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_PATH = REPO_ROOT / "integration_tests/tests/iroha_cli.rs"
PREIMAGE_SHA256 = "aa1a2f2e6113915b33107d68d255f66194bd3813f853bd031125fe4459a57d43"

HELPER_START = "struct SoracloudCli<'a>"
HELPER_END = "async fn wait_for_soracloud_json_command"
HELPER_HASH = "834a379d73e93b4efbe1d75c5899cf26e6064608a0cdd502b46f8fb9316577a9"

# Hash, bounded-success calls, bounded raw calls, shared success assertions, live network.
FUNCTION_CONTRACTS = {'soracloud_status_uses_live_torii_control_plane': ('4e4817290b210fcf8e7290a556a04959ee05a0c357413208c659b4e36f8d351d',
                                                    0,
                                                    1,
                                                    0,
                                                    True),
 'soracloud_mutations_use_live_torii_control_plane': ('490d3eb5c825479238735b71dd002760bad11819579e61b292ca443ff2c8afd0',
                                                      0,
                                                      0,
                                                      4,
                                                      True),
 'soracloud_scr_host_admission_rejects_invalid_manifests_live_torii_control_plane': ('06b3e11efa89201ed28bf3aa3ec915e18c70e51ab64fee3210552a4f9357ef60',
                                                                                     0,
                                                                                     2,
                                                                                     0,
                                                                                     True),
 'soracloud_training_and_model_weight_lifecycle_use_live_torii_control_plane': ('40dbf24c8bb2a23aa789ef9e3f1e105881629ab5d3b7b1980417d25797a4ae8a',
                                                                                17,
                                                                                0,
                                                                                0,
                                                                                True),
 'soracloud_hf_shared_lease_commands_use_live_torii_control_plane': ('8162ba24b0a3add844b47c1b730a039f040f97976c86aa6ad5cdf8d02e03d466',
                                                                     0,
                                                                     0,
                                                                     6,
                                                                     True),
 'soracloud_hf_pre_expiry_renewal_queues_and_promotes_next_window': ('3598c6aed3746dd466a64917aa96a3746b10d3b3bef049b3f7a923656d867a07',
                                                                     0,
                                                                     0,
                                                                     4,
                                                                     True),
 'soracloud_hf_shared_lease_prorates_refunds_across_multiple_accounts': ('9b5d225ebc2e75529d2ee4aa85632b8eb2e0c581874c54b83dd0671b27f0b462',
                                                                         0,
                                                                         0,
                                                                         3,
                                                                         True),
 'soracloud_templates_deploy_site_and_webapp_with_rollout_and_rollback': ('c7aace7264a816bfaa02ccdb655e998db821ca0e3f6629de5a6d26555bc74376',
                                                                          8,
                                                                          0,
                                                                          0,
                                                                          True),
 'soracloud_agent_autonomy_controls_use_live_torii_control_plane': ('088fb5c60479e33dcaa2c843f4aed6e2f8cec141328571b5c8389fc605839a42',
                                                                    4,
                                                                    0,
                                                                    0,
                                                                    True),
 'soracloud_agent_wallet_mailbox_and_lease_recovery_use_live_torii_control_plane': ('41beb959959359f9a76ccaa3371098e485674fc0096ff6977ac08dd7c2fe61f5',
                                                                                    11,
                                                                                    1,
                                                                                    0,
                                                                                    True),
 'soracloud_agent_runtime_state_recovers_after_peer_restart_live_torii_control_plane': ('39f31fcac6a263db1052d55974d7017d1835cc2d9cef5642e1f1f3b11d7b2855',
                                                                                        12,
                                                                                        0,
                                                                                        0,
                                                                                        True),
 'soracloud_agent_autonomy_control_commands_require_torii_url': ('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                                                                 0,
                                                                 0,
                                                                 0,
                                                                 False),
 'soracloud_agent_wallet_and_mailbox_commands_require_torii_url': ('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                                                                   0,
                                                                   0,
                                                                   0,
                                                                   False),
 'soracloud_agent_lease_commands_require_torii_url': ('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                                                      0,
                                                      0,
                                                      0,
                                                      False),
 'soracloud_hf_shared_lease_commands_require_torii_url': ('786257b45b50dc1d9fb961f8bd79764d912c0041c1ced3db35d02b4cea7aac88',
                                                          0,
                                                          0,
                                                          0,
                                                          False)}

REQUIRED_HELPER_TOKENS = (
    "cwd: &'a Path",
    "config: &'a ProgramConfig",
    'command.current_dir(self.cwd).arg("soracloud");',
    "command.envs(self.config.envs());",
    "Ok(command.bounded_output().await?)",
    "failure_context: &'static str",
    "output.status.success()",
    '"{context} failed with status {} and stderr: {}"',
    "$(command.arg($arg);)+",
    "$cli.bounded_output(command).await?",
    "assert_soracloud_success(&output, case.failure_context);",
)

REQUIRED_SECURITY_TOKENS = (
    "!over_cap_deploy.status.success()",
    "!no_write_deploy.status.success()",
    '.get("revoked_policy_capability_count")',
    "!expired_wallet.status.success()",
    'contains("resources.cpu_millis exceeds SCR cap")',
    'contains("binding `session_store` requires mutable writes (`ReadWrite`)")',
    '"agent.autonomy.run"',
    'contains("lease expired")',
)

FORBIDDEN_HELPER_TOKENS = (
    "Box<dyn Fn",
    "Box<dyn FnMut",
    "impl Fn",
    "callback:",
    "custom_body:",
    "escape_hatch",
)


class GuardError(AssertionError):
    """Raised when the protected SoraCloud CLI source contract changes."""


def _normalized_hash(source: str) -> str:
    return hashlib.sha256(re.sub(r"\s+", "", source).encode()).hexdigest()


def _skip_rust_non_code(source: str, index: int) -> int | None:
    if source.startswith("//", index):
        newline = source.find("\n", index + 2)
        return len(source) if newline < 0 else newline + 1
    if source.startswith("/*", index):
        depth = 1
        cursor = index + 2
        while cursor < len(source):
            if source.startswith("/*", cursor):
                depth += 1
                cursor += 2
            elif source.startswith("*/", cursor):
                depth -= 1
                cursor += 2
                if depth == 0:
                    return cursor
            else:
                cursor += 1
        return len(source)
    for prefix in ("br", "r"):
        if source.startswith(prefix, index):
            cursor = index + len(prefix)
            while cursor < len(source) and source[cursor] == "#":
                cursor += 1
            if cursor < len(source) and source[cursor] == '"':
                hashes = cursor - index - len(prefix)
                terminator = '"' + "#" * hashes
                end = source.find(terminator, cursor + 1)
                return len(source) if end < 0 else end + len(terminator)
    if source[index : index + 1] not in {'"', "'"}:
        return None
    quote = source[index]
    cursor = index + 1
    while cursor < len(source):
        if source[cursor] == "\\":
            cursor += 2
            continue
        if source[cursor] == quote:
            return cursor + 1
        cursor += 1
    return len(source)


def _matching_brace(source: str, open_index: int) -> int:
    pairs = {"(": ")", "[": "]", "{": "}"}
    stack = [pairs[source[open_index]]]
    cursor = open_index + 1
    while cursor < len(source):
        skipped = _skip_rust_non_code(source, cursor)
        if skipped is not None:
            cursor = skipped
            continue
        character = source[cursor]
        if character in pairs:
            stack.append(pairs[character])
        elif character in ")]}":
            if not stack or character != stack.pop():
                raise GuardError("mismatched Rust delimiter in protected function")
            if not stack:
                return cursor
        cursor += 1
    raise GuardError("unterminated Rust function body")


def _function(source: str, name: str) -> tuple[str, int]:
    pattern = re.compile(rf"(?m)^async fn {re.escape(name)}\b")
    matches = list(pattern.finditer(source))
    if len(matches) != 1:
        raise GuardError(f"{name}: expected one async function definition")
    start = matches[0].start()
    open_index = source.find("{", matches[0].end())
    if open_index < 0:
        raise GuardError(f"{name}: missing function body")
    end = _matching_brace(source, open_index)
    return source[start : end + 1], start


def _ordered_attributes(source: str, function_start: int) -> tuple[str, ...]:
    lines = source[:function_start].splitlines()
    attributes = []
    cursor = len(lines) - 1
    while cursor >= 0 and lines[cursor].strip().startswith("#["):
        attributes.append(lines[cursor].strip())
        cursor -= 1
    return tuple(reversed(attributes))


def _contract_surface(function: str) -> str:
    """Bind ordered bounded commands, diagnostics and direct security assertions."""
    calls = []
    for match in re.finditer(
        r"\b(?:run_bounded_soracloud_(?:command|success)!|assert(?:_eq|_ne)?!|"
        r"assert_soracloud_success|SoracloudSuccessCase::new)\s*\(", function
    ):
        opening = function.index("(", match.start(), match.end())
        closing = _matching_brace(function, opening)
        calls.append(re.sub(r"\s+", "", function[match.start():closing + 1]))
    return hashlib.sha256("\0".join(calls).encode()).hexdigest()


def _helper_region(source: str) -> str:
    if source.count(HELPER_START) != 1 or source.count(HELPER_END) != 1:
        raise GuardError("typed command helper markers must occur exactly once")
    start = source.index(HELPER_START)
    end = source.index(HELPER_END, start)
    return source[start:end]


def validate_source(source: str) -> None:
    helper = _helper_region(source)
    if _normalized_hash(helper) != HELPER_HASH:
        raise GuardError("typed SoraCloud command helper changed")
    for token in REQUIRED_HELPER_TOKENS:
        if token not in helper:
            raise GuardError(f"typed helper lost semantic token {token!r}")
    for token in FORBIDDEN_HELPER_TOKENS:
        if token in helper:
            raise GuardError(f"typed helper gained callback escape hatch {token!r}")

    protected_functions = []
    for name, (expected_hash, success_count, raw_count, assertion_count, live) in (
        FUNCTION_CONTRACTS.items()
    ):
        function, start = _function(source, name)
        protected_functions.append(function)
        if _ordered_attributes(source, start) != ("#[tokio::test]",):
            raise GuardError(f"{name}: ordered test attributes changed")
        if _contract_surface(function) != expected_hash:
            raise GuardError(f"{name}: command/assertion contract changed")
        observed = (
            function.count("run_bounded_soracloud_success!("),
            function.count("run_bounded_soracloud_command!("),
            function.count("assert_soracloud_success("),
        )
        if observed != (success_count, raw_count, assertion_count):
            raise GuardError(f"{name}: command corridor inventory changed: {observed}")
        if "tokio::process::Command::new(program())" in function:
            raise GuardError(f"{name}: direct bounded command skeleton returned")
        peer_count = function.count(".with_min_peers(4)")
        if peer_count != int(live):
            raise GuardError(f"{name}: four-peer live-network contract changed")
        context_pattern = re.compile(rf"stringify!\s*\(\s*{re.escape(name)}\s*\)")
        if live and len(context_pattern.findall(function)) != 1:
            raise GuardError(f"{name}: sandbox network context changed")

    protected = helper + "".join(protected_functions)
    for token in REQUIRED_SECURITY_TOKENS:
        if token not in protected:
            raise GuardError(f"SoraCloud adversarial contract lost token {token!r}")


def _replace_once(source: str, old: str, new: str) -> str:
    if source.count(old) != 1:
        raise AssertionError(f"mutation preimage must occur once: {old!r}")
    return source.replace(old, new, 1)


def _replace_in_function(source: str, name: str, old: str, new: str) -> str:
    function, _start = _function(source, name)
    if function.count(old) != 1:
        raise AssertionError(f"{name}: mutation preimage must occur once: {old!r}")
    return source.replace(function, function.replace(old, new, 1), 1)


class IrohaCliSoracloudCommandSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SOURCE_PATH.read_text()

    def assert_rejected(self, mutated: str) -> None:
        with self.assertRaises(GuardError):
            validate_source(mutated)

    def test_current_source_preserves_soracloud_command_contracts(self) -> None:
        validate_source(self.source)

    def test_preimage_identity_is_frozen(self) -> None:
        self.assertEqual(
            PREIMAGE_SHA256,
            "aa1a2f2e6113915b33107d68d255f66194bd3813f853bd031125fe4459a57d43",
        )

    def test_name_mutation_is_rejected(self) -> None:
        name = next(iter(FUNCTION_CONTRACTS))
        self.assert_rejected(_replace_once(self.source, f"async fn {name}", f"async fn {name}_x"))

    def test_ordered_attribute_mutation_is_rejected(self) -> None:
        name = next(iter(FUNCTION_CONTRACTS))
        old = f"#[tokio::test]\nasync fn {name}"
        self.assert_rejected(_replace_once(self.source, old, old.replace("tokio::test", "test")))

    def test_four_peer_mutation_is_rejected(self) -> None:
        name = "soracloud_status_uses_live_torii_control_plane"
        mutated = _replace_in_function(
            self.source,
            name,
            ".with_min_peers(4)",
            ".with_min_peers(3)",
        )
        self.assert_rejected(mutated)

    def test_argument_order_mutation_is_rejected(self) -> None:
        old = (
            'SoracloudSuccessCase::new("training-job-start #1");\n'
            '        "model", "training-job-start",'
        )
        new = old.replace('"model", "training-job-start"', '"training-job-start", "model"')
        self.assert_rejected(_replace_once(self.source, old, new))

    def test_success_diagnostic_mutation_is_rejected(self) -> None:
        old = 'SoracloudSuccessCase::new("training-job-start #1")'
        self.assert_rejected(_replace_once(self.source, old, old.replace("#1", "#2")))

    def test_expected_failure_polarity_mutation_is_rejected(self) -> None:
        old = "!over_cap_deploy.status.success()"
        self.assert_rejected(_replace_once(self.source, old, old.removeprefix("!")))

    def test_control_plane_diagnostic_mutation_is_rejected(self) -> None:
        old = 'assert_soracloud_success(&deploy, "hf-join");'
        self.assert_rejected(_replace_once(self.source, old, old.replace("hf-join", "hf-status")))

    def test_helper_argument_emission_mutation_is_rejected(self) -> None:
        old = "$(command.arg($arg);)+"
        self.assert_rejected(_replace_once(self.source, old, "$(command.args([$arg]);)+"))

    def test_callback_escape_hatch_is_rejected(self) -> None:
        old = "struct SoracloudSuccessCase {"
        mutated = _replace_once(
            self.source,
            old,
            "struct SoracloudSuccessCase {\n    callback: Box<dyn Fn()>,",
        )
        self.assert_rejected(mutated)

    def test_sandbox_context_mutation_is_rejected(self) -> None:
        name = "soracloud_status_uses_live_torii_control_plane"
        old = f"stringify!({name})"
        self.assert_rejected(_replace_once(self.source, old, '"wrong-network-context"'))

    def test_whitespace_growth_preserves_command_contract(self) -> None:
        validate_source(self.source + "\n" * 25_000)


if __name__ == "__main__":
    unittest.main()
