"""Native-free request-boundary checks for the public solved faucet claim digest."""

from __future__ import annotations

import ast
import re
import types
from pathlib import Path

import pytest

SOURCE = Path(__file__).resolve().parents[1] / "src" / "iroha_python"


def load_wrapper():
    """Execute the actual public wrapper without an installed native wheel."""
    module = ast.parse((SOURCE / "crypto.py").read_text())
    function = next(node for node in module.body if isinstance(node, ast.FunctionDef)
                    and node.name == "account_faucet_claim_hash_v1")
    calls = []
    native = types.SimpleNamespace(account_faucet_claim_hash_v1=
                                  lambda *args: calls.append(args) or "ab" * 32)
    namespace = {"_crypto": native, "re": re}
    exec(compile(ast.Module(body=[function], type_ignores=[]), "crypto.py", "exec"), namespace)
    return namespace["account_faucet_claim_hash_v1"], calls


def test_faucet_claim_hash_public_helper_forwards_exact_solved_claim():
    helper, calls = load_wrapper()
    assert helper("exact-account", pow_anchor_height=7, pow_nonce_hex="00ff") == "ab" * 32
    assert calls == [("exact-account", 7, "00ff")]
    for path in [SOURCE / "crypto.py", SOURCE / "__init__.py"]:
        tree = ast.parse(path.read_text())
        export_name = "__all__" if path.name == "crypto.py" else "_CRYPTO_EXPORTS"
        exports = next(node for node in tree.body
                       if isinstance(node, (ast.Assign, ast.AnnAssign))
                       and any(isinstance(target, ast.Name) and target.id == export_name
                               for target in (node.targets if isinstance(node, ast.Assign)
                                              else [node.target])))
        assert "account_faucet_claim_hash_v1" in ast.literal_eval(exports.value)


@pytest.mark.parametrize("height", [False, True, 0, -1, 1 << 64, 1.0, "1", None])
def test_faucet_claim_hash_public_helper_refuses_non_u64_anchor(height):
    helper, calls = load_wrapper()
    with pytest.raises(ValueError, match="positive u64"):
        helper("exact-account", pow_anchor_height=height, pow_nonce_hex="00")
    assert calls == []


@pytest.mark.parametrize("nonce", ["", "0", "AB", " 00", "00 ", "0x00", "gg", "00" * 33])
def test_faucet_claim_hash_public_helper_refuses_noncanonical_nonce(nonce):
    helper, calls = load_wrapper()
    with pytest.raises(ValueError, match="canonical lowercase hexadecimal"):
        helper("exact-account", pow_anchor_height=1, pow_nonce_hex=nonce)
    assert calls == []


def test_faucet_claim_hash_public_helper_requires_exact_argument_types():
    helper, calls = load_wrapper()
    with pytest.raises(TypeError, match="account_id"):
        helper(b"account", pow_anchor_height=1, pow_nonce_hex="00")
    with pytest.raises(TypeError, match="pow_nonce_hex"):
        helper("account", pow_anchor_height=1, pow_nonce_hex=b"00")
    with pytest.raises(TypeError, match="required keyword-only"):
        helper("account")
    assert calls == []
