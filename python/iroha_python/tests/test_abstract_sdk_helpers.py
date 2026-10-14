"""The current shared filter AST and Connect helpers retain their base contracts."""
from __future__ import annotations

import pytest

from iroha_python import F, Filter
from iroha_python.connect import ConnectControlPing, _ConnectControlBase


def test_python_sdk_helper_bases_are_abstract() -> None:
    with pytest.raises(TypeError, match="abstract"):
        Filter()
    with pytest.raises(TypeError, match="abstract"):
        _ConnectControlBase("Open")


def test_concrete_helpers_still_render_payloads() -> None:
    assert (F.metadata.status == "active").to_json() == {
        "op": "eq",
        "args": ["metadata.status", "active"],
    }
    assert ((F.block_height == 7) & (F.block_status == "Committed")).to_text() == (
        'block_height = 7 and block_status = "Committed"'
    )
    assert ConnectControlPing(nonce=42).to_dict() == {"nonce": 42}
