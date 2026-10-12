"""Shared helpers and constants of the SCCP Python reference (`specs/sccp.md` §0, §3.9)."""

from __future__ import annotations

import hashlib

# §3.9 constants (destination immutables and layout sizes).
MAX_VALIDITY_MS = 2_592_000_000
MAX_FAST_PAUSE_MS = 2_592_000_000
MAX_INIT_SLACK_MS = 3_600_000
MAX_CERTIFICATES_PER_CALL = 16
TON_CHECKPOINT_SLOTS = 3
MAX_VOID_FROZEN_RANGE_EVM = 256
MAX_VOID_FROZEN_RANGE_TON = 512
MAX_BLOCK_LEAVES = 512
MAX_BLOCK_PATH = 9
MAX_HISTORY_PATH = 32
MAX_HISTORY_SIZE = 1 << 32
SCCP_ANCHOR_CHUNK = 4096
U64_MAX = (1 << 64) - 1

# §0: on destinations `now_ms` is `block.timestamp × 1000` (EVM) or `now() × 1000` (TON), so the
# destination clock moves in whole seconds while Taira-side times keep millisecond precision.
DESTINATION_CLOCK_STEP_MS = 1_000

# Fixture metadata shared by `finality_v1.json`, `committee_transitions_v1.json` and
# `control_v1.json`, which the Rust reference regenerates byte for byte (ASCII only).
REFERENCE_GENERATORS = (
    "two generators write this file byte for byte: the independent Python reference "
    "(python3 scripts/sccp_reference/generate.py --write, Python 3.10+) and the Rust reference "
    "(cargo test -p iroha_sccp --test v1_reference_finality --test v1_reference_transitions "
    "--test v1_reference_control -- --ignored regenerate)"
)
DESTINATION_CLOCK_CONVENTION = (
    "`now_ms` is the destination clock: block.timestamp (EVM) or now() (TON) in whole seconds, times 1000, so every "
    "`now_ms` is a multiple of 1000"
)
SCENARIO_CLOCK_CONVENTION = (
    "within a scenario `now_ms` never decreases from one step to the next (equal values are calls in the same block "
    "or second). Taira-side times (`X.timestamp_ms`, `untilMs`, payload deadlines, fast-pause expiries) are "
    "milliseconds and may be sub-second, so a time boundary is probed with the nearest whole-second clock values on "
    "both sides"
)


def be(value: int, width: int) -> bytes:
    """Big-endian unsigned integer of exactly `width` bytes."""
    if value < 0 or value >= 1 << (8 * width):
        raise ValueError(f"{value} does not fit in {width} bytes")
    return value.to_bytes(width, "big")


def be32(value: int) -> bytes:
    return be(value, 4)


def be64(value: int) -> bytes:
    return be(value, 8)


def word(value: int) -> bytes:
    """The 32-byte ABI word of an unsigned integer (§0)."""
    return be(value, 32)


def saturating_u64_sum(a: int, b: int) -> int:
    """`min(a + b, 2^64 − 1)` of two `u64` values.

    No destination call aborts for arithmetic (§5.1.2): the two time sums of the
    contracts, a rotation's `t_eff(X) + X.validity_ms` and the fast-pause bound
    `now_ms + MAX_FAST_PAUSE_MS`, saturate at the largest `u64`.
    """
    if not (0 <= a <= U64_MAX and 0 <= b <= U64_MAX):
        raise ValueError(f"saturating_u64_sum takes u64 operands, got {a} and {b}")
    return min(a + b, U64_MAX)


def check_destination_clock(now_ms: int, previous_ms: int | None = None, where: str = "step") -> None:
    """Fail unless `now_ms` is a destination clock value that may follow `previous_ms`.

    A destination reads whole seconds (`now_ms = block.timestamp × 1000`, §0) and
    its clock never runs backwards; consecutive calls may share one value.
    """
    if now_ms < 0 or now_ms % DESTINATION_CLOCK_STEP_MS:
        raise AssertionError(f"{where}: now_ms {now_ms} is not a whole-second destination clock value")
    if previous_ms is not None and now_ms < previous_ms:
        raise AssertionError(f"{where}: now_ms {now_ms} is earlier than the previous step's {previous_ms}")


def sha256(*parts: bytes) -> bytes:
    return hashlib.sha256(b"".join(parts)).digest()


def h_iroha(*parts: bytes) -> bytes:
    """`iroha_crypto::Hash`: Blake2b-256 with the low bit of the last byte forced to 1."""
    digest = bytearray(hashlib.blake2b(b"".join(parts), digest_size=32).digest())
    digest[-1] |= 1
    return bytes(digest)


def rep(byte: int, count: int = 32) -> bytes:
    """`byte` repeated `count` times (the `0xNN^32` notation of the spec)."""
    return bytes([byte]) * count


def hx(data: bytes) -> str:
    """0x-prefixed lowercase hex, the fixture byte-string convention."""
    return "0x" + data.hex()


def unhex(text: str) -> bytes:
    if not text.startswith("0x"):
        raise ValueError(f"expected 0x-prefixed hex: {text!r}")
    return bytes.fromhex(text[2:])


class SccpError(Exception):
    """A rejection named after the §5.2.2 error table (or a layout invariant id)."""

    def __init__(self, name: str, detail: str = "", **args):
        super().__init__(f"{name}: {detail}" if detail else name)
        self.name = name
        self.detail = detail
        self.args_map = args
