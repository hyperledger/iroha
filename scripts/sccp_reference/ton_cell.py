"""Structural TON burn admission, independent of the Acton builder (§5.3.2/§5.3.4)."""

from __future__ import annotations

from dataclasses import dataclass

from .common import SccpError
from .payload import MAX_TAIRA_ACCOUNT_BYTES

TON_SNAKE_CHUNK_BYTES = 127
TON_BURN_TO_TAIRA_OP = 0x53434254


@dataclass(frozen=True)
class TonCell:
    """Raw message-cell shape; exotic cells stay explicit and are never resolved."""

    bits: str
    refs: tuple[TonCell, ...] = ()
    exotic: bool = False


def snake_bytes(data: bytes) -> TonCell:
    """Build the unique ordinary snake for a nonempty byte string."""
    if not data:
        raise SccpError("BadSnake")
    chunks = [data[i:i + TON_SNAKE_CHUNK_BYTES] for i in range(0, len(data), TON_SNAKE_CHUNK_BYTES)]
    tail = None
    for chunk in reversed(chunks):
        tail = TonCell("".join(f"{byte:08b}" for byte in chunk), () if tail is None else (tail,))
    assert tail is not None
    return tail


def parse_taira_recipient(root: TonCell) -> bytes:
    """Admit every ordinary canonical chunk, with the wallet/minter error order."""
    data = bytearray()
    cell = root
    while True:
        bits, refs = len(cell.bits), len(cell.refs)
        if cell.exotic or set(cell.bits) - {"0", "1"}:
            raise SccpError("BadSnake")
        if refs == 1:
            if bits != TON_SNAKE_CHUNK_BYTES * 8:
                raise SccpError("BadSnake")
            if len(data) + TON_SNAKE_CHUNK_BYTES >= MAX_TAIRA_ACCOUNT_BYTES:
                raise SccpError("BadRecipient")
        elif refs != 0 or not 8 <= bits <= TON_SNAKE_CHUNK_BYTES * 8 or bits % 8:
            raise SccpError("BadSnake")
        elif len(data) + bits // 8 > MAX_TAIRA_ACCOUNT_BYTES:
            raise SccpError("BadRecipient")
        data.extend(int(cell.bits[i:i + 8], 2) for i in range(0, bits, 8))
        if refs == 0:
            return bytes(data)
        cell = cell.refs[0]


def burn_to_taira_payload(recipient: bytes) -> TonCell:
    """Build the exact ordinary wrapper and its admitted 1..=1024-byte recipient."""
    if len(recipient) > MAX_TAIRA_ACCOUNT_BYTES:
        raise SccpError("BadRecipient")
    return TonCell(f"{TON_BURN_TO_TAIRA_OP:032b}", (snake_bytes(recipient),))
