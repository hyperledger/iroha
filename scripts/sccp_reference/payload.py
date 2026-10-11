"""Profiles, transfer payloads, payload hashes and message ids (`specs/sccp.md` §2, §3.1–§3.3)."""

from __future__ import annotations

from dataclasses import dataclass

from .common import SccpError, be, be32, be64, word
from .keccak import keccak256

PAYLOAD_TAG = b"SCCP/PAYLOAD/V1"
MESSAGE_TAG = b"SCCP/MESSAGE/V1"
MAX_PAYLOAD_BYTES = 4096


@dataclass(frozen=True)
class Profile:
    """One first-release profile (§2.1, §2.3)."""

    name: str
    tag: int
    domain: int
    route_id: str | None
    account_codec: int


TAIRA = Profile("sora-taira", 0x40, 0, None, 3)
ETHEREUM = Profile("ethereum-mainnet", 0x41, 1, "taira_eth_xor", 2)
BSC = Profile("bsc-mainnet", 0x42, 2, "taira_bsc_xor", 2)
TON = Profile("ton-mainnet", 0x44, 4, "taira_ton_xor", 7)
PROFILES = (TAIRA, ETHEREUM, BSC, TON)
EXTERNAL = (ETHEREUM, BSC, TON)
BY_NAME = {p.name: p for p in PROFILES}
BY_DOMAIN = {p.domain: p for p in PROFILES}

CODEC_CANONICAL_TEXT = 1
CODEC_EVM_ADDRESS20 = 2
CODEC_TAIRA_ACCOUNT = 3
CODEC_TON_ACCOUNT36 = 7


def identity_word(profile: Profile, taira_network_id: bytes) -> bytes:
    """§2.1 identity word."""
    if profile is TAIRA:
        if len(taira_network_id) != 32:
            raise ValueError("Taira NetworkId must be 32 bytes")
        return taira_network_id
    if profile is ETHEREUM:
        return word(1)
    if profile is BSC:
        return word(56)
    if profile is TON:
        return ((1 << 256) - 239).to_bytes(32, "big")
    raise ValueError(profile)


def network_bytes(profile: Profile, taira_network_id: bytes) -> bytes:
    """`tag ‖ identity_word` (33 bytes)."""
    return bytes([profile.tag]) + identity_word(profile, taira_network_id)


def lane_bytes(source: Profile, target: Profile, taira_network_id: bytes) -> bytes:
    """`network_bytes(source) ‖ network_bytes(target)` (66 bytes); exactly one endpoint is Taira."""
    if (source is TAIRA) == (target is TAIRA):
        raise ValueError("a lane has exactly one Taira endpoint")
    return network_bytes(source, taira_network_id) + network_bytes(target, taira_network_id)


@dataclass(frozen=True)
class Payload:
    """A decoded §3.2 transfer payload."""

    source_domain: int
    dest_domain: int
    nonce: int
    route_revision: int
    deadline_ms: int
    amount: int
    sender_codec: int
    sender: bytes
    recipient_codec: int
    recipient: bytes
    route_id: str
    asset_id: str = "xor"


def _codec_for(source: Profile, dest: Profile) -> tuple[int, int]:
    if source is TAIRA:
        return CODEC_TAIRA_ACCOUNT, dest.account_codec
    return source.account_codec, CODEC_TAIRA_ACCOUNT


def validate_account(codec: int, data: bytes) -> None:
    """Codec validity of §3.1 (`BadPayload` otherwise)."""
    if codec == CODEC_CANONICAL_TEXT:
        ok = 1 <= len(data) <= 256 and all(0x21 <= b <= 0x7E for b in data)
    elif codec == CODEC_EVM_ADDRESS20:
        ok = len(data) == 20 and any(data)
    elif codec == CODEC_TAIRA_ACCOUNT:
        ok = 1 <= len(data) <= 1024
    elif codec == CODEC_TON_ACCOUNT36:
        ok = len(data) == 36 and data[:4] == bytes(4) and any(data[4:])
    else:
        ok = False
    if not ok:
        raise SccpError("BadPayload", f"invalid account for codec {codec}")


def encode_payload(p: Payload) -> bytes:
    """Encode a §3.2 payload after checking every rule (raises `BadPayload`)."""
    out = (
        bytes([0x02, 0x01])
        + be32(p.source_domain)
        + be32(p.dest_domain)
        + be64(p.nonce)
        + be32(p.route_revision)
        + be64(p.deadline_ms)
        + be32(0)
        + bytes([CODEC_CANONICAL_TEXT])
        + be(len(p.asset_id), 2)
        + p.asset_id.encode("ascii")
        + be(p.amount, 16)
        + bytes([p.sender_codec])
        + be(len(p.sender), 2)
        + p.sender
        + bytes([p.recipient_codec])
        + be(len(p.recipient), 2)
        + p.recipient
        + bytes([CODEC_CANONICAL_TEXT])
        + be(len(p.route_id), 2)
        + p.route_id.encode("ascii")
    )
    decode_payload(out)
    return out


def decode_payload(data: bytes, *, check_recipient: bool = True) -> Payload:
    """Decode and validate a §3.2 payload; any violation raises `SccpError("BadPayload")`.

    With `check_recipient=False` only the recipient's codec length is checked, so
    that a destination can report the recipient rules of §5.1.5 as `BadRecipient`.
    """

    def fail(why: str) -> SccpError:
        return SccpError("BadPayload", why)

    if len(data) > MAX_PAYLOAD_BYTES:
        raise fail("payload exceeds 4096 bytes")
    pos = 0

    def take(n: int) -> bytes:
        nonlocal pos
        if pos + n > len(data):
            raise fail("truncated")
        chunk = data[pos : pos + n]
        pos += n
        return chunk

    def uint(n: int) -> int:
        return int.from_bytes(take(n), "big")

    if take(1) != b"\x02" or take(1) != b"\x01":
        raise fail("kind/version")
    source_domain = uint(4)
    dest_domain = uint(4)
    nonce = uint(8)
    route_revision = uint(4)
    deadline_ms = uint(8)
    if uint(4) != 0:
        raise fail("asset_home_domain")
    if uint(1) != CODEC_CANONICAL_TEXT:
        raise fail("asset codec")
    asset_id = take(uint(2))
    validate_account(CODEC_CANONICAL_TEXT, asset_id)
    amount = uint(16)
    sender_codec = uint(1)
    sender = take(uint(2))
    recipient_codec = uint(1)
    recipient = take(uint(2))
    if uint(1) != CODEC_CANONICAL_TEXT:
        raise fail("route id codec")
    route_id = take(uint(2))
    validate_account(CODEC_CANONICAL_TEXT, route_id)
    if pos != len(data):
        raise fail("trailing bytes")
    if source_domain not in BY_DOMAIN or dest_domain not in BY_DOMAIN:
        raise fail("unknown domain")
    source, dest = BY_DOMAIN[source_domain], BY_DOMAIN[dest_domain]
    if source is dest or (source is TAIRA) == (dest is TAIRA):
        raise fail("exactly one endpoint must be Taira")
    if route_revision == 0:
        raise fail("zero revision")
    if (deadline_ms != 0) != (source is TAIRA):
        raise fail("deadline rule")
    if amount == 0 or ((source is TON or dest is TON) and amount >= 1 << 96):
        raise fail("amount")
    if asset_id != b"xor":
        raise fail("asset id")
    if (sender_codec, recipient_codec) != _codec_for(source, dest):
        raise fail("codecs")
    validate_account(sender_codec, sender)
    if check_recipient:
        validate_account(recipient_codec, recipient)
    elif len(recipient) != {CODEC_EVM_ADDRESS20: 20, CODEC_TON_ACCOUNT36: 36}.get(recipient_codec, len(recipient)) or not (
        1 <= len(recipient) <= 1024
    ):
        raise fail("recipient length")
    external = dest if source is TAIRA else source
    if route_id.decode("ascii") != external.route_id:
        raise fail("route id")
    return Payload(
        source_domain,
        dest_domain,
        nonce,
        route_revision,
        deadline_ms,
        amount,
        sender_codec,
        sender,
        recipient_codec,
        recipient,
        route_id.decode("ascii"),
        asset_id.decode("ascii"),
    )


def payload_hash(payload: bytes) -> bytes:
    """`keccak256("SCCP/PAYLOAD/V1" ‖ payload)` (§3.3)."""
    return keccak256(PAYLOAD_TAG, payload)


def message_id(source: Profile, target: Profile, taira_network_id: bytes, payload: bytes) -> bytes:
    """`keccak256("SCCP/MESSAGE/V1" ‖ lane_bytes ‖ payload_hash)` (§3.3)."""
    return keccak256(MESSAGE_TAG, lane_bytes(source, target, taira_network_id), payload_hash(payload))


def outbound_payload(
    target: Profile,
    nonce: int,
    route_revision: int,
    deadline_ms: int,
    amount: int,
    sender: bytes,
    recipient: bytes,
) -> bytes:
    """A Taira→`target` transfer payload (§4.4 step 11)."""
    return encode_payload(
        Payload(
            source_domain=0,
            dest_domain=target.domain,
            nonce=nonce,
            route_revision=route_revision,
            deadline_ms=deadline_ms,
            amount=amount,
            sender_codec=CODEC_TAIRA_ACCOUNT,
            sender=sender,
            recipient_codec=target.account_codec,
            recipient=recipient,
            route_id=target.route_id,
        )
    )
