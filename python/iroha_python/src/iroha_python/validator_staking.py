"""Canonical V1 staking value codecs using the existing Norito and identity owners.

These typed values preserve signed monetary intent. They do not authenticate
network XOR, ledger observations, possession, finality, or committee authority.
Every field is an explicit constructor argument; fee_claim is mandatory.
"""
from __future__ import annotations

from dataclasses import dataclass

from norito.codec import NoritoDecoder, NoritoEncoder
from norito.header import COMPACT_LEN

from .address import (
    AccountAddress, AddressClass, AddressHeader, ControllerPayload, CurveId,
    MultisigControllerPayload, MultisigMember,
    asset_definition_id_from_bytes, asset_definition_id_to_bytes,
)
from .crypto import NetworkId, parse_public_key_multihash, public_key_multihash
from .numeric_v1 import KotodamaQuantity


class _Value:
    """Immutable, validated model base; no stored wire bytes or alternate decoder."""
    def __post_init__(self) -> None:
        for field, kind in _SCHEMAS[type(self)]:
            object.__setattr__(self, field, _normalize(kind, getattr(self, field)))
        _validate(self)

    def to_norito(self) -> bytes:
        """Encode this exact value using the sole compact V1 layout."""
        return _encode(type(self), self)

    @classmethod
    def from_norito(cls, payload: bytes):
        """Reject alternate layouts, noncanonical values and trailing bytes."""
        payload = _bytes(payload)
        value = _decode(cls, payload)
        if value.to_norito() != payload:
            raise ValueError("staking value is not byte-canonical")
        return value


@dataclass(frozen=True)
class StakingScopeV1(_Value):
    """Genesis scope (None) or one exact genesis-derived network."""
    network_id: NetworkId | None


@dataclass(frozen=True)
class StakingAssetScopeV1(_Value):
    """Global scope (None) or one exact dataspace balance bucket."""
    dataspace: int | None


@dataclass(frozen=True)
class StakingAssetIdV1(_Value):
    """Exact domainless account, canonical asset definition and balance scope."""
    account: str
    definition: str
    scope: StakingAssetScopeV1


@dataclass(frozen=True)
class StakingPeerIdV1(_Value):
    """Complete canonical peer key, validated by the existing native key owner."""
    public_key: str


@dataclass(frozen=True)
class StakingMonetaryRegistrationV1(_Value):
    """Exact initial eligibility height."""
    activation_height: int


@dataclass(frozen=True)
class StakingMonetaryBondV1(_Value):
    """Exact existing tenure and peer binding."""
    activation_height: int
    peer_id: StakingPeerIdV1


@dataclass(frozen=True)
class StakingMonetaryUnbondV1(_Value):
    """Exact tenure and marked 32-byte withdrawal record commitment."""
    activation_height: int
    request_hash: bytes


@dataclass(frozen=True)
class StakingMonetarySlashV1(_Value):
    """Exact tenure and pre-slash custody exposure."""
    activation_height: int
    slashable_exposure: KotodamaQuantity


StakingMonetaryPreconditionV1 = (StakingMonetaryRegistrationV1 | StakingMonetaryBondV1 |
                               StakingMonetaryUnbondV1 | StakingMonetarySlashV1)


@dataclass(frozen=True)
class StakingMonetaryPlanV1(_Value):
    """Exact positive transfer and operation-specific signed precondition."""
    network_scope: StakingScopeV1
    valid_until_height: int
    source_asset: StakingAssetIdV1
    destination_asset: StakingAssetIdV1
    amount: KotodamaQuantity
    precondition: StakingMonetaryPreconditionV1


@dataclass(frozen=True)
class StakingFeeRewardClaimV1(_Value):
    """Complete reserved fee credit and the exact beneficiary/lifecycle sequence."""
    lifecycle_seal: bytes
    beneficiary_id: str
    beneficiary_revision: int
    source_asset: StakingAssetIdV1
    destination_asset: StakingAssetIdV1
    amount: KotodamaQuantity
    expected_claim_sequence: int


@dataclass(frozen=True)
class StakingRewardClaimPlanV1(_Value):
    """Exact automatically accrued funded XOR claim and execution expiry."""
    network_scope: StakingScopeV1
    valid_until_height: int
    fee_claim: StakingFeeRewardClaimV1


@dataclass(frozen=True)
class StakingValidatorGenerationV1(_Value):
    """Ordered BLS roster under one generation; not an authority proof."""
    network_id: NetworkId
    generation: int
    validators: tuple[StakingPeerIdV1, ...]


@dataclass(frozen=True)
class StakingInstalledBeaconV1(_Value):
    """Exact installed session and finalized transcript identities."""
    session_id: bytes
    transcript_hash: bytes


@dataclass(frozen=True)
class StakingEpochAuthorizationV1(_Value):
    """Exact epoch bounds and decision under one explicit signing generation."""
    version: int
    network_id: NetworkId
    epoch: int
    first_height: int
    last_height: int
    authority_generation: int
    authority_id: bytes
    beacon: StakingInstalledBeaconV1 | None
    previous_authorization_id: bytes
    transition_id: bytes
    decision: str


@dataclass(frozen=True)
class StakingPrepareRegistrationV1(_Value):
    """Exact validator, peer and self-bond selected by the operator."""
    validator: str
    peer_id: StakingPeerIdV1
    amount: KotodamaQuantity
    candidate: bool


@dataclass(frozen=True)
class StakingPrepareBondV1(_Value):
    """Exact additional self stake or delegation."""
    validator: str
    staker: str
    amount: KotodamaQuantity


@dataclass(frozen=True)
class StakingPrepareUnbondV1(_Value):
    """One exact retained withdrawal request; this does not request exit."""
    validator: str
    staker: str
    request_id: bytes


@dataclass(frozen=True)
class StakingPrepareClaimV1(_Value):
    """Current beneficiary requesting one automatic entitlement claim."""
    recipient: str


StakingPreparationOperationV1 = (StakingPrepareRegistrationV1 | StakingPrepareBondV1 |
                               StakingPrepareUnbondV1 | StakingPrepareClaimV1)


@dataclass(frozen=True)
class StakingPreparationRequestV1(_Value):
    """Exact read-only operator intent, never a signed transaction."""
    lane_id: int
    valid_for_blocks: int
    operation: StakingPreparationOperationV1


@dataclass(frozen=True)
class StakingPreparationBalanceV1(_Value):
    """Observed balance and independent additive reserves for an exact asset."""
    asset: StakingAssetIdV1
    balance: KotodamaQuantity
    stake_reserved: KotodamaQuantity
    rewards_reserved: KotodamaQuantity


@dataclass(frozen=True)
class StakingPreparationV1(_Value):
    """Coherent server observation; reported block identity is not a state proof."""
    request: StakingPreparationRequestV1
    network_id: NetworkId
    observed_height: int
    observed_block_hash: bytes
    observed_ledger_time_ms: int
    assumed_execution_height: int
    xor_asset_definition_id: str
    plan: StakingMonetaryPlanV1 | StakingRewardClaimPlanV1
    balances: tuple[StakingPreparationBalanceV1, ...]


_PREPARATION_OPERATIONS = (StakingPrepareRegistrationV1, StakingPrepareBondV1,
                           StakingPrepareUnbondV1, StakingPrepareClaimV1)
_PREPARED_PLANS = (StakingMonetaryPlanV1, StakingRewardClaimPlanV1)


_PRECONDITIONS = (StakingMonetaryRegistrationV1, StakingMonetaryBondV1,
                  StakingMonetaryUnbondV1, StakingMonetarySlashV1)
_DECISIONS = ("genesis", "activate", "retain", "retain_and_cancel")
_ALGORITHMS = ("ed25519", "secp256k1", "bls_normal", "bls_small", "ml-dsa",
               "gost3410-2012-256-paramset-a", "gost3410-2012-256-paramset-b",
               "gost3410-2012-256-paramset-c", "gost3410-2012-512-paramset-a",
               "gost3410-2012-512-paramset-b", "sm2")
_CURVES = tuple(CurveId.from_algorithm(name) for name in _ALGORITHMS)
_SCHEMAS = {
    StakingPrepareRegistrationV1: (("validator", "account"), ("peer_id", StakingPeerIdV1), ("amount", "quantity"), ("candidate", "bool")),
    StakingPrepareBondV1: (("validator", "account"), ("staker", "account"), ("amount", "quantity")),
    StakingPrepareUnbondV1: (("validator", "account"), ("staker", "account"), ("request_id", "hash")),
    StakingPrepareClaimV1: (("recipient", "account"),),
    StakingPreparationRequestV1: (("lane_id", "lane"), ("valid_for_blocks", "u64"), ("operation", "preparation_operation")),
    StakingPreparationBalanceV1: (("asset", StakingAssetIdV1), ("balance", "quantity"), ("stake_reserved", "quantity"), ("rewards_reserved", "quantity")),
    StakingPreparationV1: (("request", StakingPreparationRequestV1), ("network_id", "network"), ("observed_height", "u64"), ("observed_block_hash", "hash"), ("observed_ledger_time_ms", "u64"), ("assumed_execution_height", "u64"), ("xor_asset_definition_id", "definition"), ("plan", "prepared_plan"), ("balances", ("vector", StakingPreparationBalanceV1, 2))),
    StakingScopeV1: (("network_id", ("option", "network")),),
    StakingAssetScopeV1: (("dataspace", ("option", "u64")),),
    StakingAssetIdV1: (("account", "account"), ("definition", "definition"), ("scope", StakingAssetScopeV1)),
    StakingPeerIdV1: (("public_key", "key"),),
    StakingMonetaryRegistrationV1: (("activation_height", "u64"),),
    StakingMonetaryBondV1: (("activation_height", "u64"), ("peer_id", StakingPeerIdV1)),
    StakingMonetaryUnbondV1: (("activation_height", "u64"), ("request_hash", "hash")),
    StakingMonetarySlashV1: (("activation_height", "u64"), ("slashable_exposure", "quantity")),
    StakingMonetaryPlanV1: (("network_scope", StakingScopeV1), ("valid_until_height", "u64"), ("source_asset", StakingAssetIdV1), ("destination_asset", StakingAssetIdV1), ("amount", "quantity"), ("precondition", "precondition")),
    StakingFeeRewardClaimV1: (("lifecycle_seal", "bytes32"), ("beneficiary_id", "account"), ("beneficiary_revision", "u64"), ("source_asset", StakingAssetIdV1), ("destination_asset", StakingAssetIdV1), ("amount", "quantity"), ("expected_claim_sequence", "u64")),
    StakingRewardClaimPlanV1: (("network_scope", StakingScopeV1), ("valid_until_height", "u64"), ("fee_claim", StakingFeeRewardClaimV1)),
    StakingValidatorGenerationV1: (("network_id", "network"), ("generation", "u64"), ("validators", ("vector", StakingPeerIdV1, 31))),
    StakingInstalledBeaconV1: (("session_id", "bytes32"), ("transcript_hash", "bytes32")),
    StakingEpochAuthorizationV1: (("version", "u16"), ("network_id", "network"), ("epoch", "u64"), ("first_height", "u64"), ("last_height", "u64"), ("authority_generation", "u64"), ("authority_id", "bytes32"), ("beacon", "beacon"), ("previous_authorization_id", "bytes32"), ("transition_id", "bytes32"), ("decision", "decision")),
}


def _bytes(value) -> bytes:
    if type(value) not in (bytes, bytearray, memoryview):
        raise TypeError("expected byte storage")
    return bytes(value)


def _normalize(kind, value):
    if kind in _SCHEMAS:
        if type(value) is not kind: raise TypeError(f"expected {kind.__name__}")
        return value
    if isinstance(kind, tuple):
        if kind[0] == "option": return None if value is None else _normalize(kind[1], value)
        if type(value) not in (tuple, list) or len(value) > kind[2]: raise ValueError("staking vector exceeds its bound")
        return tuple(_normalize(kind[1], item) for item in value)
    if kind == "lane":
        if type(value) is not int or not 0 <= value < 1 << 32: raise ValueError("expected lane u32")
    elif kind == "bool":
        if type(value) is not bool: raise TypeError("expected bool")
    elif kind in ("preparation_operation", "prepared_plan"):
        allowed = _PREPARATION_OPERATIONS if kind == "preparation_operation" else _PREPARED_PLANS
        if type(value) not in allowed: raise TypeError("expected exact typed preparation value")
    elif kind in ("u16", "u64"):
        if type(value) is not int or not 0 <= value < 1 << int(kind[1:]): raise ValueError(f"expected {kind}")
    elif kind == "network":
        if not isinstance(value, NetworkId): raise TypeError("expected NetworkId")
    elif kind in ("hash", "bytes32"):
        value = _bytes(value)
        if len(value) != 32 or kind == "hash" and not value[-1] & 1: raise ValueError("invalid 32-byte identity")
    elif kind == "account":
        if type(value) is not str: raise TypeError("expected canonical account address")
        address = AccountAddress.from_i105(value)
        if address.to_i105() != value: raise ValueError("noncanonical account address")
    elif kind == "definition": asset_definition_id_to_bytes(value)
    elif kind == "key":
        algorithm, key = parse_public_key_multihash(value)
        value = public_key_multihash(algorithm, key)
    elif kind == "quantity":
        if type(value) is not KotodamaQuantity: raise TypeError("expected KotodamaQuantity")
    elif kind == "precondition":
        if type(value) not in _PRECONDITIONS: raise TypeError("expected typed monetary precondition")
    elif kind == "beacon":
        if value is not None and type(value) is not StakingInstalledBeaconV1: raise TypeError("expected exact installed beacon or None")
    elif kind == "decision":
        if value not in _DECISIONS: raise ValueError("unknown epoch decision")
    else: raise TypeError("unknown staking field")
    return value


def _same_asset(left, right):
    return left.definition == right.definition and left.scope == right.scope


def _account_order(text):
    controller = AccountAddress.from_i105(text).controller
    if isinstance(controller, ControllerPayload):
        return (0, (_CURVES.index(controller.curve), controller.public_key))
    return (1, controller.version, controller.threshold,
            tuple((_CURVES.index(member.curve), member.public_key, member.weight) for member in controller.members))


def _asset_order(asset):
    ds = asset.scope.dataspace
    return (_account_order(asset.account), asset_definition_id_to_bytes(asset.definition), (0, 0) if ds is None else (1, ds))


def _validate(value):
    if type(value) is StakingPreparationRequestV1 and value.valid_for_blocks == 0:
        raise ValueError("preparation expiry offset must be positive")
    if type(value) in (StakingPrepareRegistrationV1, StakingPrepareBondV1) and value.amount.mantissa == 0:
        raise ValueError("preparation amount must be positive")
    if type(value) is StakingMonetaryPlanV1:
        if value.valid_until_height == 0 or value.amount.mantissa == 0 or not _same_asset(value.source_asset, value.destination_asset): raise ValueError("invalid staking monetary plan")
    elif type(value) is StakingFeeRewardClaimV1:
        if not any(value.lifecycle_seal) or value.amount.mantissa == 0 or value.source_asset.scope.dataspace is not None or value.destination_asset.scope.dataspace is not None or not _same_asset(value.source_asset, value.destination_asset): raise ValueError("invalid fee reward custody or amount")
    elif type(value) is StakingRewardClaimPlanV1:
        if value.valid_until_height == 0: raise ValueError("reward expiry must be positive")
    elif type(value) is StakingValidatorGenerationV1:
        if len(value.validators) < 4 or (len(value.validators) - 1) % 3:
            raise ValueError("invalid validator-generation geometry")
        previous_key = None
        for peer in value.validators:
            algorithm, key = parse_public_key_multihash(peer.public_key)
            if algorithm != "bls_normal" or len(key) != 48:
                raise ValueError("validator generation requires BLS-normal keys")
            if previous_key is not None and previous_key >= key:
                raise ValueError("validator generation requires strictly ordered keys")
            previous_key = key
    elif type(value) is StakingEpochAuthorizationV1:
        if value.version != 1 or value.first_height == 0 or value.last_height < value.first_height: raise ValueError("invalid epoch authorization")


def _uint(value, bits):
    encoder = NoritoEncoder(COMPACT_LEN); encoder.write_uint(value, bits); return encoder.finish()


def _record(parts):
    encoder = NoritoEncoder(COMPACT_LEN)
    for part in parts:
        encoder.write_length(len(part), compact=True); encoder.write_bytes(part)
    return encoder.finish()


def _parts(payload, count):
    decoder = NoritoDecoder(payload, COMPACT_LEN)
    result = [decoder.read_bytes(decoder.read_length(compact=True)) for _ in range(count)]
    if decoder.remaining(): raise ValueError("trailing staking record bytes")
    return result


def _vector(payload, limit):
    decoder = NoritoDecoder(payload, COMPACT_LEN); count = decoder.read_uint(64)
    if count > limit or count > decoder.remaining(): raise ValueError("staking vector exceeds bound or source geometry")
    result = [decoder.read_bytes(decoder.read_length(compact=True)) for _ in range(count)]
    if decoder.remaining(): raise ValueError("trailing staking vector bytes")
    return result


def _variant(payload):
    decoder = NoritoDecoder(payload, COMPACT_LEN); tag = decoder.read_uint(32)
    return tag, decoder.read_bytes(decoder.remaining())


def _key_encode(algorithm, key):
    # Native parsing/validation precedes canonical Norito composition.
    algorithm, key = parse_public_key_multihash(public_key_multihash(algorithm, key))
    raw = bytes((_CURVES.index(CurveId.from_algorithm(algorithm)),)) + key
    return _uint(len(raw), 64) + _record(bytes((byte,)) for byte in raw)


def _key_decode(payload):
    elements = _vector(payload, 8259)
    if not elements or any(len(item) != 1 for item in elements): raise ValueError("invalid public key byte geometry")
    raw = b"".join(elements)
    if raw[0] >= len(_ALGORITHMS): raise ValueError("unknown key algorithm")
    algorithm = _ALGORITHMS[raw[0]]
    literal = public_key_multihash(algorithm, raw[1:])
    parse_public_key_multihash(literal)
    return literal


def _account_encode(text):
    controller = AccountAddress.from_i105(text).controller
    if isinstance(controller, ControllerPayload):
        return _uint(0, 32) + _record([_key_encode(_ALGORITHMS[_CURVES.index(controller.curve)], controller.public_key)])
    members = [_record([_key_encode(_ALGORITHMS[_CURVES.index(member.curve)], member.public_key), _uint(member.weight, 16)]) for member in controller.members]
    policy = _record([_uint(controller.version, 8), _uint(controller.threshold, 16), _uint(len(members), 64) + _record(members)])
    return _uint(1, 32) + _record([policy])


def _account_decode(payload):
    tag, body = _variant(payload); part, = _parts(body, 1)
    if tag == 0:
        algorithm, key = parse_public_key_multihash(_key_decode(part))
        controller = ControllerPayload.single_key(key, algorithm)
        class_ = AddressClass.SINGLE_KEY
    elif tag == 1:
        version, threshold, member_bytes = _parts(part, 3)
        members = []
        for item in _vector(member_bytes, 65535):
            key, weight = _parts(item, 2)
            algorithm, raw = parse_public_key_multihash(_key_decode(key))
            members.append(MultisigMember(CurveId.from_algorithm(algorithm), raw, _decode("u16", weight)))
        controller = MultisigControllerPayload(_decode("u8", version), _decode("u16", threshold), tuple(members))
        class_ = AddressClass.MULTI_SIG
    else: raise ValueError("unknown account controller")
    return AccountAddress(AddressHeader.new(0, class_, 1), controller).to_i105()


def _encode(kind, value):
    if kind is StakingScopeV1:
        return _uint(0, 32) if value.network_id is None else _uint(1, 32) + _record([value.network_id.to_bytes()])
    if kind is StakingAssetScopeV1:
        return _uint(0, 32) if value.dataspace is None else _uint(1, 32) + _record([_uint(value.dataspace, 64)])
    if kind in _SCHEMAS: return _record(_encode(field_kind, getattr(value, name)) for name, field_kind in _SCHEMAS[kind])
    if isinstance(kind, tuple):
        if kind[0] == "option": return b"\0" if value is None else b"\1" + _record([_encode(kind[1], value)])
        return _uint(len(value), 64) + _record(_encode(kind[1], item) for item in value)
    if kind == "lane": return _record([_uint(value, 32)])
    if kind == "bool": return bytes((int(value),))
    if kind in ("preparation_operation", "prepared_plan"):
        variants = _PREPARATION_OPERATIONS if kind == "preparation_operation" else _PREPARED_PLANS
        return _uint(variants.index(type(value)), 32) + _record([value.to_norito()])
    if kind in ("u8", "u16", "u32", "u64"): return _uint(value, int(kind[1:]))
    if kind == "network": return value.to_bytes()
    if kind in ("bytes32", "hash"): return value
    if kind == "key": return _key_encode(*parse_public_key_multihash(value))
    if kind == "account": return _account_encode(value)
    if kind == "definition": return _record(bytes((byte,)) for byte in asset_definition_id_to_bytes(value))
    if kind == "quantity":
        mantissa = value.mantissa
        raw = mantissa.to_bytes((mantissa.bit_length() + 8) // 8, "little", signed=True) if mantissa else b""
        return _record([_uint(len(raw), 32) + raw, _uint(value.scale, 32)])
    if kind == "precondition": return _uint(_PRECONDITIONS.index(type(value)), 32) + _record([value.to_norito()])
    if kind == "beacon": return _uint(0, 32) if value is None else _uint(1, 32) + _record([value.to_norito()])
    if kind == "decision": return _uint(_DECISIONS.index(value), 32)
    raise TypeError("unknown staking value")


def _decode(kind, payload):
    if kind in (StakingScopeV1, StakingAssetScopeV1):
        tag, body = _variant(payload)
        if tag == 0:
            if body: raise ValueError("unit variant has trailing bytes")
            return kind(None)
        if tag != 1: raise ValueError("unknown scope")
        part, = _parts(body, 1)
        return kind(_decode("network" if kind is StakingScopeV1 else "u64", part))
    if kind in _SCHEMAS:
        return kind(*(_decode(field_kind, part) for (_, field_kind), part in zip(_SCHEMAS[kind], _parts(payload, len(_SCHEMAS[kind])))))
    if isinstance(kind, tuple):
        if kind[0] == "vector": return tuple(_decode(kind[1], item) for item in _vector(payload, kind[2]))
        if payload == b"\0": return None
        if payload[:1] != b"\1": raise ValueError("invalid optional field")
        part, = _parts(payload[1:], 1); return _decode(kind[1], part)
    if kind == "lane":
        part, = _parts(payload, 1); return _decode("u32", part)
    if kind == "bool":
        if payload not in (b"\0", b"\1"): raise ValueError("invalid canonical bool")
        return payload == b"\1"
    if kind in ("preparation_operation", "prepared_plan"):
        variants = _PREPARATION_OPERATIONS if kind == "preparation_operation" else _PREPARED_PLANS
        tag, body = _variant(payload)
        if tag >= len(variants): raise ValueError("unknown preparation variant")
        part, = _parts(body, 1); return _decode(variants[tag], part)
    if kind in ("u8", "u16", "u32", "u64"):
        decoder = NoritoDecoder(payload, COMPACT_LEN); value = decoder.read_uint(int(kind[1:]))
        if decoder.remaining(): raise ValueError("trailing unsigned bytes")
        return value
    if kind == "network": return NetworkId.from_bytes(payload)
    if kind in ("bytes32", "hash"): return _normalize(kind, payload)
    if kind == "key": return _key_decode(payload)
    if kind == "account": return _account_decode(payload)
    if kind == "definition":
        parts = _parts(payload, 16)
        if any(len(part) != 1 for part in parts): raise ValueError("invalid UUID field geometry")
        return asset_definition_id_from_bytes(b"".join(parts))
    if kind == "quantity":
        mantissa, scale = _parts(payload, 2); decoder = NoritoDecoder(mantissa, COMPACT_LEN)
        count = decoder.read_uint(32)
        if count > 64: raise ValueError("quantity mantissa exceeds 512 bits")
        raw = decoder.read_bytes(count)
        if decoder.remaining(): raise ValueError("trailing quantity mantissa")
        scale_decoder = NoritoDecoder(scale, COMPACT_LEN); value = scale_decoder.read_uint(32)
        if scale_decoder.remaining(): raise ValueError("trailing quantity scale")
        return KotodamaQuantity(int.from_bytes(raw, "little", signed=True), value)
    if kind == "precondition":
        tag, body = _variant(payload)
        if tag >= len(_PRECONDITIONS): raise ValueError("unknown monetary precondition")
        part, = _parts(body, 1); return _decode(_PRECONDITIONS[tag], part)
    if kind == "beacon":
        tag, body = _variant(payload)
        if tag == 0 and not body: return None
        if tag != 1: raise ValueError("unknown or noncanonical beacon binding")
        part, = _parts(body, 1); return _decode(StakingInstalledBeaconV1, part)
    if kind == "decision":
        tag, body = _variant(payload)
        if tag >= len(_DECISIONS) or body: raise ValueError("unknown or noncanonical epoch decision")
        return _DECISIONS[tag]
    raise TypeError("unknown staking value")


__all__ = [kind.__name__ for kind in _SCHEMAS] + ["StakingMonetaryPreconditionV1"]


_PREPARATION_FRAMES = {
    StakingPreparationRequestV1: ("PublicLanePreparationRequestV1", 64 * 1024),
    StakingPreparationV1: ("PublicLanePreparationV1", 256 * 1024),
}


def _preparation_schema(kind):
    import hashlib
    return hashlib.sha256(b"norito:v1:type-name\0iroha_data_model::nexus::staking_preparation::" + _PREPARATION_FRAMES[kind][0].encode("ascii")).digest()[:16]


def encode_staking_preparation_frame_v1(value: StakingPreparationRequestV1 | StakingPreparationV1) -> bytes:
    """Encode the exact schema-bound canonical V1 observation frame."""
    from norito.header import NoritoHeader
    from norito.crc64 import crc64
    kind = type(value)
    if kind not in _PREPARATION_FRAMES: raise TypeError("expected preparation request or response")
    payload = value.to_norito()
    if len(payload) > _PREPARATION_FRAMES[kind][1] - 40: raise ValueError("staking preparation exceeds its frame bound")
    return NoritoHeader(_preparation_schema(kind), len(payload), crc64(payload), COMPACT_LEN).encode() + payload


def decode_staking_preparation_frame_v1(kind, frame: bytes):
    """Reject alternate schema/layout/padding, truncation and oversized observations."""
    from norito.header import NoritoHeader
    if kind not in _PREPARATION_FRAMES: raise TypeError("expected preparation request or response type")
    if type(frame) is not bytes: raise TypeError("preparation frame must be immutable bytes")
    if len(frame) > _PREPARATION_FRAMES[kind][1]: raise ValueError("staking preparation exceeds its frame bound")
    header, payload = NoritoHeader.decode(frame, expected_schema_hash=_preparation_schema(kind), expected_flags=COMPACT_LEN)
    if header.compression != 0 or len(frame) != 40 + header.payload_length: raise ValueError("preparation requires the exact uncompressed frame")
    header.validate_checksum(payload)
    value = kind.from_norito(payload)
    if encode_staking_preparation_frame_v1(value) != frame: raise ValueError("preparation frame is not byte-canonical")
    return value


def validate_staking_preparation_v1(prepared: StakingPreparationV1, request: StakingPreparationRequestV1,
                                    network_id: NetworkId, xor_asset_definition_id: str) -> StakingPreparationV1:
    """Bind an observation to exact intent and operator pins; this authenticates no state."""
    _normalize("network", network_id); _normalize("definition", xor_asset_definition_id)
    def fail(field): raise ValueError("staking preparation response binding: " + field)
    if type(prepared) is not StakingPreparationV1 or type(request) is not StakingPreparationRequestV1: raise TypeError("expected typed preparation")
    if prepared.request.to_norito() != request.to_norito(): fail("request")
    if prepared.network_id.to_bytes() != network_id.to_bytes(): fail("network_id")
    if prepared.xor_asset_definition_id != xor_asset_definition_id: fail("xor_asset_definition_id")
    expiry = prepared.observed_height + request.valid_for_blocks
    if prepared.observed_height == 0 or prepared.assumed_execution_height != prepared.observed_height + 1 or expiry >= 1 << 64: fail("height")
    plan, intent = prepared.plan, request.operation
    if plan.network_scope.network_id is None or plan.network_scope.network_id.to_bytes() != network_id.to_bytes() or plan.valid_until_height != expiry: fail("plan_scope_or_expiry")
    assets = []
    if type(plan) is StakingMonetaryPlanV1:
        matched = (type(intent) is StakingPrepareRegistrationV1 and type(plan.precondition) is StakingMonetaryRegistrationV1 and plan.source_asset.account == intent.validator and plan.amount == intent.amount
            or type(intent) is StakingPrepareBondV1 and type(plan.precondition) is StakingMonetaryBondV1 and plan.source_asset.account == intent.staker and plan.amount == intent.amount
            or type(intent) is StakingPrepareUnbondV1 and type(plan.precondition) is StakingMonetaryUnbondV1 and plan.destination_asset.account == intent.staker)
        if not matched or plan.precondition.activation_height == 0: fail("monetary_intent")
        assets.extend((plan.source_asset, plan.destination_asset))
    else:
        if type(intent) is not StakingPrepareClaimV1: fail("reward_intent")
        if plan.fee_claim.destination_asset.account != intent.recipient: fail("reward_recipient")
        assets.extend((plan.fee_claim.source_asset, plan.fee_claim.destination_asset))
    unique = sorted(set(assets), key=_asset_order)
    if tuple(row.asset for row in prepared.balances) != tuple(unique): fail("balances")
    if any(asset.scope.dataspace is not None or asset.definition != xor_asset_definition_id for asset in unique): fail("global_xor")
    return prepared


__all__ += ["StakingPreparationOperationV1", "encode_staking_preparation_frame_v1", "decode_staking_preparation_frame_v1", "validate_staking_preparation_v1"]
