"""Full-controller identity parity against the required native cryptographic owner."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from iroha_native import require_account_codec_v1
from iroha_torii_client import _account_id

from iroha_python import AccountAddress
from iroha_python.address import AddressClass, AddressHeader, CurveId, MultisigMember
from iroha_python.crypto import AccountId

ROOT = Path(__file__).resolve().parents[3]
FIXTURE = json.loads((ROOT / "fixtures/account/multisig_wire_v1.json").read_text())


def _literal_for_malformed_bytes(raw: bytes) -> str:
    # Only test data construction: admit no identity and bypass no production guard.
    # This independently computes a checksum-valid envelope so parse negatives test
    # key admission rather than accidentally failing the checksum first.
    value = int.from_bytes(raw, "big")
    digits = []
    while value:
        value, digit = divmod(value, 105)
        digits.append(digit)
    digits.reverse()
    values = []
    bits = accumulator = 0
    for byte in raw:
        accumulator = (accumulator << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            values.append((accumulator >> bits) & 31)
    if bits:
        values.append((accumulator << (5 - bits)) & 31)
    hrp = "snx"
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    checksum = 1
    for value in expanded + values + [0] * 6:
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for bit, generator in enumerate((0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)):
            if (top >> bit) & 1:
                checksum ^= generator
    checksum ^= 0x2BC830A3
    return "sora" + "".join(_account_id.I105_ALPHABET[digit] for digit in digits + [(checksum >> (5 * (5 - i))) & 31 for i in range(6)])


def _malformed_keys():
    cases = [(1, b"\x01" + bytes(31)), (1, b"\xff" * 32), (4, b"\x02" + b"\xff" * 32),
             (3, b"\xff" * 48), (5, b"\xff" * 96), (2, bytes(1952))]
    cases += [(curve, b"\xff" * (128 if curve >= 13 else 64)) for curve in (10, 11, 12, 13, 14)]
    cases.append((15, b"\x00\x00\x04" + b"\xff" * 64))
    return cases


@pytest.mark.parametrize("item", FIXTURE["positive"], ids=lambda item: item["name"])
def test_all_full_controller_owners_preserve_rust_fixture(item):
    native = require_account_codec_v1()
    assert FIXTURE["schema"] == "iroha.account.multisig-wire.v1"
    assert item["layout_flags"] == 2
    raw = bytes.fromhex(item["canonical_address_hex"])
    address = AccountAddress.from_canonical_bytes(raw)
    assert address.to_i105(753) == item["i105"]
    assert AccountAddress.parse_encoded(item["i105"]).canonical_bytes() == raw
    assert AccountAddress.from_i105(item["i105"]).canonical_bytes() == raw
    assert _account_id.decode_canonical_i105_account_id(item["i105"]) == raw
    assert _account_id.encode_i105_account_id(raw, 753) == item["i105"]
    assert str(AccountId(item["i105"])) == item["i105"]
    assert bytes(native._encode_account_id_v1(item["i105"])[1]) == bytes.fromhex(item["account_id_frame_hex"])
    # Generic typed instruction identities retain their complete controller.
    instructions = (
        native.Instruction.register_account(item["i105"], None),
        native.Instruction.set_account_key_value(item["i105"], "label", "full-controller"),
        native.Instruction.remove_account_key_value(item["i105"], "label"),
        native.Instruction.grant_account_permission(item["i105"], "CanSetAccountKeyValue"),
        native.Instruction.revoke_account_permission(item["i105"], "CanSetAccountKeyValue"),
    )
    for instruction in instructions:
        encoded = instruction.to_json()
        assert native.Instruction.from_json(encoded, chain_discriminant=753).to_json() == encoded
    network = native.NetworkId.parse("hash:" + "A5" * 32 + "#95D7")
    builder = native.TransactionBuilder(network, item["i105"], json.dumps({"payer": "authority", "value": {"charge_limits": [], "gas_limit": None}}), chain_discriminant=753)
    builder.add_instruction(instructions[0])
    assert json.loads(builder.payload_json())["authority"] == item["i105"]
    if item["name"] != "ed25519":
        # Unsigned identity support does not broaden the Ed25519 signing contract.
        with pytest.raises(ValueError):
            builder.sign(bytes(32))
        with pytest.raises(ValueError):
            builder.build_with_signature(bytes(64))
    policy = item["policy"]
    if policy is None:
        offset = 4 if raw[1] == 0 else 5
        rebuilt = AccountAddress.from_account(public_key=raw[offset:], algorithm=item["name"])
        assert AccountId(item["i105"]).public_key_hex == raw[offset:].hex()
    else:
        members = tuple(MultisigMember(CurveId(member["curve_id"]), bytes.fromhex(member["public_key_hex"]), member["weight"]) for member in policy["members"])
        rebuilt = AccountAddress.from_multisig_policy(version=policy["version"], threshold=policy["threshold"], members=members[::-1])
        assert rebuilt.controller.members == members
        assert rebuilt.controller.threshold == policy["threshold"]
        with pytest.raises(ValueError, match="single"):
            _ = AccountId(item["i105"]).public_key_hex
    assert rebuilt.canonical_bytes() == raw
    for padding in (" ", "\t", "\r\n", "\u00a0", "\u2003", "\u202f", "\u3000"):
        for literal in (padding + item["i105"], item["i105"] + padding):
            for parse in (AccountAddress.parse_encoded, AccountAddress.from_i105, AccountId, _account_id.decode_canonical_i105_account_id):
                with pytest.raises(ValueError):
                    parse(literal)


@pytest.mark.parametrize("curve,key", _malformed_keys())
def test_complete_native_owner_rejects_all_twelve_malformed_keys(curve, key):
    native = require_account_codec_v1()
    raw = bytes((2, 0, curve, len(key))) + key if len(key) <= 255 else bytes((2, 2, curve)) + len(key).to_bytes(2, "big") + key
    literal = _literal_for_malformed_bytes(raw)
    algorithm = next(item["name"] for item in FIXTURE["positive"][:11] if bytes.fromhex(item["canonical_address_hex"])[2] == curve)
    for operation in (
        lambda: native._validate_account_address_v1(raw),
        lambda: AccountAddress.from_account(public_key=key, algorithm=algorithm),
        lambda: MultisigMember(CurveId(curve), key, 1),
        lambda: AccountAddress.from_canonical_bytes(raw),
        lambda: AccountAddress.parse_encoded(literal),
        lambda: AccountId(literal),
        lambda: _account_id.validate_canonical_account_id_bytes(raw),
        lambda: _account_id.decode_canonical_i105_account_id(literal),
        lambda: _account_id.encode_i105_account_id(raw, 753),
    ):
        with pytest.raises(ValueError):
            operation()
    # The native parse error must concern key admission, not our generated checksum.
    with pytest.raises(ValueError, match="public key"):
        native._parse_account_address_v1(literal, 753)
    from iroha_python.address import ControllerPayload
    with pytest.raises(ValueError):
        AccountAddress(AddressHeader.new(0, AddressClass.SINGLE_KEY, 1), ControllerPayload(0 if len(key) <= 255 else 2, CurveId(curve), key))


def test_loaded_native_owner_rejects_replaced_or_removed_module(monkeypatch):
    import sys
    import types

    from iroha_native import NativeUnavailableError

    native = require_account_codec_v1()
    fake = types.ModuleType(native.__name__)
    fake.__dict__.update(native.__dict__)
    fake._validate_account_address_v1 = lambda _value: None
    with monkeypatch.context() as patch:
        patch.setitem(sys.modules, native.__name__, fake)
        with pytest.raises(NativeUnavailableError, match="replaced its native owner module"):
            require_account_codec_v1()
    assert require_account_codec_v1() is native
    with monkeypatch.context() as patch:
        patch.delitem(sys.modules, native.__name__)
        with pytest.raises(NativeUnavailableError, match="replaced its native owner module"):
            require_account_codec_v1()
    assert require_account_codec_v1() is native


def test_public_controller_key_coercion_is_bounded_before_allocation():
    from iroha_python.address import ControllerPayload

    # An integer is a byte allocation request to bytes(), never a public key.
    for key in (64 * 1024 * 1024, iter((1, 2, 3)), bytes(65536)):
        for constructor in (
            lambda key=key: ControllerPayload(0, CurveId.ED25519, key),
            lambda key=key: MultisigMember(CurveId.ED25519, key, 1),
        ):
            with pytest.raises(ValueError, match="bytes-like|positive u16"):
                constructor()
