"""Canonical account identities admitted exclusively by the Rust native owner.

Anonymous HTTP transport does not load native code. Account construction,
parsing, and controller inspection require the separate ``iroha-native`` wheel.
"""
from __future__ import annotations

from typing import Optional, Tuple

BASE58_ALPHABET = tuple(
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
)
IROHA_POEM_KANA_HALFWIDTH = (
    "ｲ",
    "ﾛ",
    "ﾊ",
    "ﾆ",
    "ﾎ",
    "ﾍ",
    "ﾄ",
    "ﾁ",
    "ﾘ",
    "ﾇ",
    "ﾙ",
    "ｦ",
    "ﾜ",
    "ｶ",
    "ﾖ",
    "ﾀ",
    "ﾚ",
    "ｿ",
    "ﾂ",
    "ﾈ",
    "ﾅ",
    "ﾗ",
    "ﾑ",
    "ｳ",
    "ヰ",
    "ﾉ",
    "ｵ",
    "ｸ",
    "ﾔ",
    "ﾏ",
    "ｹ",
    "ﾌ",
    "ｺ",
    "ｴ",
    "ﾃ",
    "ｱ",
    "ｻ",
    "ｷ",
    "ﾕ",
    "ﾒ",
    "ﾐ",
    "ｼ",
    "ヱ",
    "ﾋ",
    "ﾓ",
    "ｾ",
    "ｽ",
)
I105_ALPHABET = BASE58_ALPHABET + IROHA_POEM_KANA_HALFWIDTH
I105_INDEX = {symbol: index for index, symbol in enumerate(I105_ALPHABET)}
I105_BASE = len(I105_ALPHABET)
I105_CHECKSUM_LEN = 6
I105_BECH32M_CONST = 0x2BC830A3
I105_SENTINELS = ("sora", "test", "dev")
I105_SENTINEL_DISCRIMINANTS = {"sora": 0x02F1, "test": 0x0171, "dev": 0}
I105_NUMERIC_SENTINEL_PREFIX = "n"
I105_DISCRIMINANT_MAX = 0xFFFF

def parse_i105_sentinel_and_payload(encoded: str) -> Tuple[str, int, str]:
    """Return the literal sentinel, chain discriminant, and encoded payload."""

    if not isinstance(encoded, str):
        raise ValueError("i105 address must be a string")
    for sentinel in I105_SENTINELS:
        if encoded.startswith(sentinel):
            return (
                sentinel,
                I105_SENTINEL_DISCRIMINANTS[sentinel],
                encoded[len(sentinel) :],
            )
    if encoded.startswith(I105_NUMERIC_SENTINEL_PREFIX):
        index = len(I105_NUMERIC_SENTINEL_PREFIX)
        while index < len(encoded) and "0" <= encoded[index] <= "9":
            index += 1
        if index > len(I105_NUMERIC_SENTINEL_PREFIX):
            discriminant = int(
                encoded[len(I105_NUMERIC_SENTINEL_PREFIX) : index]
            )
            if discriminant > I105_DISCRIMINANT_MAX:
                raise ValueError(
                    "i105 chain discriminant must fit in an unsigned 16-bit integer"
                )
            return encoded[:index], discriminant, encoded[index:]
    raise ValueError("i105 address is missing the expected chain-discriminant sentinel")


def _native_account_codec():
    try:
        from iroha_native import require_account_codec_v1
    except ImportError as error:
        raise RuntimeError(
            "account identities require the installed ABI-29 iroha-native wheel"
        ) from error
    return require_account_codec_v1()


def _discriminant(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= I105_DISCRIMINANT_MAX:
        raise ValueError("i105 chain discriminant must fit in an unsigned 16-bit integer")
    return value


def validate_canonical_account_id_bytes(canonical: bytes) -> None:
    """Admit full controller bytes with complete Rust key and policy validation."""
    if not isinstance(canonical, bytes):
        raise TypeError("canonical account-address bytes must be bytes")
    _native_account_codec()._validate_account_address_v1(canonical)


def encode_i105_account_id(canonical: bytes, discriminant: int) -> str:
    """Render an admitted full controller with its exact canonical I105 sentinel."""
    if not isinstance(canonical, bytes):
        raise TypeError("canonical account-address bytes must be bytes")
    return _native_account_codec()._render_account_address_v1(canonical, _discriminant(discriminant))


def decode_i105_account_id(encoded: str, *, expected_discriminant: Optional[int] = None) -> bytes:
    """Decode one exact canonical I105 identity using the Rust address owner."""
    if not isinstance(encoded, str):
        raise ValueError("i105 address must be a string")
    if expected_discriminant is not None:
        expected_discriminant = _discriminant(expected_discriminant)
    return bytes(_native_account_codec()._parse_account_address_v1(encoded, expected_discriminant))


def decode_canonical_i105_account_id(encoded: str, *, expected_discriminant: Optional[int] = None) -> bytes:
    """Admit an exact canonical I105 identity and return its full controller."""
    return decode_i105_account_id(encoded, expected_discriminant=expected_discriminant)
