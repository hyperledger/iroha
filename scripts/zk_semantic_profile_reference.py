#!/usr/bin/env python3
"""Independent reference for semantic profile identities and the frozen FASTPQ transcript.

Requires Python 3.9+ and its standard library; nothing is downloaded and no
environment variable is read. The module shares no code with the Rust owners
(`crates/fastpq_isi/src/semantic_profile.rs`,
`crates/fastpq_prover/src/backend/transcript_profile.rs`, `deep_binding.rs`,
`compact_sha3.rs`, `crates/fastpq_isi/src/compact_challenge.rs`). It is used by
`scripts/check_zk_primitive_workloads.py` to recompute every frozen profile
identity and the transcript known answers of
`fixtures/fastpq/q77-transcript-profile.json`.

What it implements

* The canonical semantic profile frame and its SHA3-256 identity.
* The subset of canonical Norito framing the transcript uses: the 40-byte
  header (magic, version, nominal schema hash, length, CRC-64/XZ, layout flag),
  compact field lengths, fixed-width integers, byte vectors and sequences.
* The statement context, prefix and body frames of the frozen transcript, the
  ten atomic SHAKE256 tapes, the nine SHA3-256 chain commitments and the
  bounded decoders (word rejection, out-of-domain point, query positions).

Agreement of this model with the Rust owners on the recorded known answers
shows that both implement the same byte-level transcript. It is not a security
argument and establishes no soundness level.

Run as a script:

* no argument: self-test against hand-written vectors;
* `--print-fixture SPEC`: print the transcript fixture for the transcript
  profile recorded in SPEC (`specs/zk_primitive_workloads.json`);
* `--write-fixture SPEC`: write that fixture to the path SPEC records.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import struct
import sys
from typing import Any, Sequence

MAGIC = b"iroha:semantic-profile:v1\0"
KINDS = (
    "transcript",
    "native-commitment",
    "in-circuit-digest",
    "standard-primitive",
    "key-derivation",
    "lattice-trapdoor",
)
VALUE_TYPES = ("u64", "text", "bytes", "u64-list")
LABEL = re.compile(r"[a-z0-9]+(?:[._-][a-z0-9]+)*\Z")
MAX_PARAMETERS = 255
MAX_LABEL_BYTES = 96
MAX_VALUE_BYTES = 64 * 1024
U64_MAX = (1 << 64) - 1

FIXTURE_FORMAT = "iroha.fastpq.transcript_known_answers.v1"


class ProfileError(ValueError):
    """A parameter list is not a canonical semantic profile."""


def _length(value: int) -> bytes:
    return struct.pack("<I", value)


def _bytes(value: bytes) -> bytes:
    if len(value) > MAX_VALUE_BYTES:
        raise ProfileError("value exceeds its byte ceiling")
    return _length(len(value)) + value


def _label(text: Any, what: str) -> bytes:
    if not isinstance(text, str) or not LABEL.match(text) or len(text) > MAX_LABEL_BYTES:
        raise ProfileError(f"{what} {text!r} is outside the label grammar")
    return text.encode("ascii")


def encode_profile(kind: str, name: str, parameters: Sequence[dict[str, Any]]) -> bytes:
    """Canonical frame of one semantic profile.

    `parameters` is the ordered list of `{"key", "type", "value"}` entries of a
    record: `u64` holds an integer, `text` a string, `bytes` a lower-case
    hexadecimal string and `u64-list` a list of integers.
    """
    if kind not in KINDS:
        raise ProfileError(f"unknown profile kind {kind!r}")
    if len(parameters) > MAX_PARAMETERS:
        raise ProfileError("too many parameters")
    out = bytearray(MAGIC)
    out += _bytes(kind.encode("ascii"))
    out += _bytes(_label(name, "profile name"))
    out += _length(len(parameters))
    seen: set[str] = set()
    for parameter in parameters:
        if not isinstance(parameter, dict) or set(parameter) != {"key", "type", "value"}:
            raise ProfileError("a parameter is exactly a key, a type and a value")
        key, kind_of, value = parameter["key"], parameter["type"], parameter["value"]
        out += _bytes(_label(key, "parameter key"))
        if key in seen:
            raise ProfileError(f"parameter key {key!r} is repeated")
        seen.add(key)
        if kind_of == "u64":
            if type(value) is not int or not 0 <= value <= U64_MAX:
                raise ProfileError(f"{key}: not a u64")
            out += b"\x01" + struct.pack("<Q", value)
        elif kind_of == "text":
            if not isinstance(value, str):
                raise ProfileError(f"{key}: not text")
            out += b"\x02" + _bytes(value.encode("utf-8"))
        elif kind_of == "bytes":
            if not isinstance(value, str) or not re.fullmatch(r"(?:[0-9a-f]{2})*", value):
                raise ProfileError(f"{key}: not lower-case hexadecimal bytes")
            out += b"\x03" + _bytes(bytes.fromhex(value))
        elif kind_of == "u64-list":
            if (
                not isinstance(value, list)
                or len(value) > MAX_VALUE_BYTES // 8
                or any(type(item) is not int or not 0 <= item <= U64_MAX for item in value)
            ):
                raise ProfileError(f"{key}: not a bounded list of u64")
            out += b"\x04" + _length(len(value)) + b"".join(struct.pack("<Q", item) for item in value)
        else:
            raise ProfileError(f"{key}: unknown value type {kind_of!r}")
    return bytes(out)


def profile_identity(frame: bytes) -> str:
    """Lower-case hexadecimal SHA3-256 identity of a canonical profile frame."""
    return hashlib.sha3_256(frame).hexdigest()


SET_MAGIC = b"iroha:semantic-profile-set:v1\0"


def profile_set_identity(identities: Sequence[str]) -> str:
    """One identity for the ordered profile identities a measurement depends on."""
    members = [bytes.fromhex(identity) for identity in identities]
    if any(len(member) != 32 for member in members):
        raise ProfileError("a profile identity has 32 bytes")
    return hashlib.sha3_256(SET_MAGIC + _length(len(members)) + b"".join(members)).hexdigest()


def identity_of(profile: dict[str, Any]) -> str:
    """Identity of a recorded profile entry (`kind`, `name`, `parameters`)."""
    return profile_identity(encode_profile(profile["kind"], profile["name"], profile["parameters"]))


def parameter_map(profile: dict[str, Any]) -> dict[str, Any]:
    """Parameter values of a recorded profile by key."""
    return {parameter["key"]: parameter["value"] for parameter in profile["parameters"]}


# --- Canonical Norito framing subset -----------------------------------------------------------


def varint(value: int) -> bytes:
    """Compact little-endian base-128 length."""
    out = bytearray()
    while True:
        low = value & 0x7F
        value >>= 7
        if value:
            out.append(low | 0x80)
        else:
            out.append(low)
            return bytes(out)


def field(payload: bytes) -> bytes:
    """One struct field or sequence element: compact length, then payload."""
    return varint(len(payload)) + payload


def u16(value: int) -> bytes:
    return struct.pack("<H", value)


def u32(value: int) -> bytes:
    return struct.pack("<I", value)


def u64(value: int) -> bytes:
    return struct.pack("<Q", value)


def string(text: str) -> bytes:
    data = text.encode("utf-8")
    return varint(len(data)) + data


def byte_vector(data: bytes) -> bytes:
    return u64(len(data)) + data


def array_u32(values: Sequence[int]) -> bytes:
    return b"".join(field(u32(value)) for value in values)


def _crc64_table() -> list[int]:
    polynomial = 0xC96C5795D7870F42  # CRC-64/XZ, reflected
    table = []
    for index in range(256):
        value = index
        for _ in range(8):
            value = (value >> 1) ^ polynomial if value & 1 else value >> 1
        table.append(value)
    return table


_CRC64 = _crc64_table()


def crc64(data: bytes) -> int:
    """CRC-64/XZ."""
    value = U64_MAX
    for byte in data:
        value = _CRC64[(value ^ byte) & 0xFF] ^ (value >> 8)
    return value ^ U64_MAX


def schema_hash(name: str) -> bytes:
    """Nominal Norito schema hash of a frame name."""
    return hashlib.sha256(b"norito:v1:type-name\0" + name.encode("utf-8")).digest()[:16]


def frame(name: str, payload: bytes) -> bytes:
    """Canonical uncompressed Norito frame with the compact-length layout."""
    return (
        b"NRT0"
        + b"\0\0"
        + schema_hash(name)
        + b"\0"
        + u64(len(payload))
        + u64(crc64(payload))
        + b"\x02"
        + payload
    )


# --- Frozen transcript model -------------------------------------------------------------------


class Abort(Exception):
    """The finite decoder of one tape failed; the attempt is over."""


class TranscriptModel:
    """The frozen transcript for one statement, driven by a recorded profile."""

    def __init__(
        self,
        profile: dict[str, Any],
        catalog: str,
        relation: str,
        layout: str,
        statement: bytes,
    ) -> None:
        self.values = parameter_map(profile)
        values = self.values
        self.modulus = values["field_modulus"]
        self.tapes = values["tape_bytes"]
        context = frame(
            values["context_frame"],
            b"".join(
                [
                    field(string(relation)),
                    field(string(layout)),
                    field(u32(values["trace_rows"])),
                    field(u32(values["evaluation_rows"])),
                    field(u32(values["committed_columns"])),
                    field(u32(values["constraints"])),
                    field(u64(self.modulus)),
                    field(u64(values["extension_nonresidue"])),
                    field(u64(values["evaluation_root"])),
                    field(u64(values["coset_offset"])),
                    field(array_u32(values["fri_arities"])),
                    field(array_u32(values["fri_lengths"])),
                    field(array_u32(values["fri_degree_bounds"])),
                    field(u32(values["queries"])),
                    field(u32(values["query_candidates"])),
                    field(byte_vector(statement)),
                ]
            ),
        )
        self.context = context
        self.prefix = frame(
            values["prefix_frame"],
            b"".join(
                [
                    field(u16(values["framing_version"])),
                    field(byte_vector(catalog.encode("utf-8"))),
                    field(byte_vector(values["construction"].encode("utf-8"))),
                    field(byte_vector(encode_profile(profile["kind"], profile["name"], profile["parameters"]))),
                    field(byte_vector(context)),
                ]
            ),
        )
        self.predecessor = bytes(values["commitment_bytes"])
        self.round = 1
        self.pending: bytes | None = None

    def body(self, kind: int, oracle: int, rnd: int, level: int, position: int, output: int, fields: Sequence[bytes]) -> bytes:
        sequence = u64(len(fields)) + b"".join(field(byte_vector(item)) for item in fields)
        return frame(
            self.values["body_frame"],
            b"".join(
                [
                    field(bytes([kind])),
                    field(bytes([oracle])),
                    field(bytes([rnd])),
                    field(u32(level)),
                    field(u32(position)),
                    field(u32(output)),
                    field(sequence),
                ]
            ),
        )

    def hash(self, body: bytes) -> bytes:
        return hashlib.sha3_256(self.prefix + body).digest()

    def leaf(self, oracle: int, rnd: int, position: int, payload: bytes) -> bytes:
        return self.hash(self.body(1, oracle, rnd, 0, position, self.values["commitment_bytes"], [payload]))

    def parent(self, oracle: int, rnd: int, level: int, index: int, left: bytes, right: bytes) -> bytes:
        return self.hash(self.body(2, oracle, rnd, level, index, self.values["commitment_bytes"], [left, right]))

    def ood_commitment(self, answers: bytes) -> bytes:
        return self.leaf(5, 0, 0, answers)

    def challenge(self) -> bytes:
        """Materialize the whole raw tape of the current round."""
        if self.pending is not None or self.round > len(self.tapes):
            raise Abort("out of sequence")
        extent = self.tapes[self.round - 1]
        body = self.body(4, 0, self.round, 0, 0, extent, [self.predecessor])
        tape = hashlib.shake_256(self.prefix + body).digest(extent)
        self.pending = tape
        if self.round == len(self.tapes):
            self.round += 1
            self.pending = None
        return tape

    def commit(self, commitment: bytes) -> bytes:
        """Chain the whole pending tape with the next commitment."""
        if self.pending is None:
            raise Abort("out of sequence")
        body = self.body(3, 0, self.round, 0, 0, self.values["commitment_bytes"], [self.pending, commitment])
        self.predecessor = self.hash(body)
        self.pending = None
        self.round += 1
        return self.predecessor

    def accepted_words(self, tape: bytes) -> list[int]:
        words = struct.unpack(f"<{len(tape) // 8}Q", tape)
        return [word for word in words if word < self.modulus]

    def fields(self, tape: bytes, count: int) -> list[list[int]]:
        words = self.accepted_words(tape)
        if len(words) < 4 * count:
            raise Abort("exhausted")
        return [words[4 * index : 4 * index + 4] for index in range(count)]

    def ood_point(self, tape: bytes) -> list[int]:
        point = self.fields(tape, 1)[0]
        if not any(point[1:]):
            raise Abort("base-field out-of-domain point")
        return point

    def queries(self, tape: bytes) -> list[int]:
        values = self.values
        words = self.accepted_words(tape)
        if len(words) < values["query_candidates"]:
            raise Abort("exhausted")
        rows = values["evaluation_rows"]
        limit = self.modulus - self.modulus % rows
        chosen: set[int] = set()
        for candidate in words[: values["query_candidates"]]:
            if candidate >= limit:
                continue
            chosen.add(candidate % rows)
            if len(chosen) == values["queries"]:
                return sorted(chosen)
        raise Abort("exhausted")


def _sha3(data: bytes) -> str:
    return hashlib.sha3_256(data).hexdigest()


def _words(values: Sequence[Sequence[int]]) -> bytes:
    return b"".join(struct.pack("<4Q", *value) for value in values)


def known_answers(profile: dict[str, Any], inputs: dict[str, Any]) -> dict[str, Any]:
    """Every observable value of one complete transcript run.

    `inputs` names the catalog, relation identity, column layout and statement,
    and seeds for the nine commitments. Commitments are public test values:
    each root is SHA3-256 of its seed label, and out-of-domain answer `i` has
    coefficients `4i+1 .. 4i+4`.
    """
    statement = bytes.fromhex(inputs["statement_hex"])
    model = TranscriptModel(profile, inputs["catalog"], inputs["relation"], inputs["layout"], statement)
    values = model.values
    seed = inputs["commitment_seed"]
    root = lambda label: hashlib.sha3_256(f"{seed}:{label}".encode("utf-8")).digest()  # noqa: E731
    answers = _words([[4 * index + lane + 1 for lane in range(4)] for index in range(values["ood_answers"])])
    commitments = [
        ("row-root", root("row-root")),
        ("quotient+mask-root", root("quotient+mask-root")),
        ("ood-answers", model.ood_commitment(answers)),
        *[(f"fri-root-{index}", root(f"fri-root-{index}")) for index in range(len(values["fri_arities"]))],
        ("terminal-root", root("terminal-root")),
    ]
    rounds = []
    decoded: dict[str, Any] = {}
    for ordinal in range(1, len(values["tape_bytes"]) + 1):
        tape = model.challenge()
        entry: dict[str, Any] = {"round": ordinal, "tape_bytes": len(tape), "tape_sha3_256": _sha3(tape)}
        if ordinal == 2:
            alphas = model.fields(tape, values["constraints"])
            decoded["alphas_sha3_256"] = _sha3(_words(alphas))
            decoded["first_alpha"] = alphas[0]
            decoded["last_alpha"] = alphas[-1]
        elif ordinal == 3:
            decoded["ood_point"] = model.ood_point(tape)
        elif ordinal == 4:
            decoded["lambda"] = model.fields(tape, 1)[0]
        elif 5 <= ordinal <= 9:
            decoded.setdefault("betas", []).append(model.fields(tape, 1)[0])
        elif ordinal == 10:
            decoded["queries"] = model.queries(tape)
        if ordinal <= len(commitments):
            label, commitment = commitments[ordinal - 1]
            entry["commitment"] = label
            entry["commitment_hex"] = commitment.hex()
            entry["chain_sha3_256"] = model.commit(commitment).hex()
        rounds.append(entry)
    widths = [
        ("row", 1, 0, values["committed_columns"] * 8),
        ("quotient+mask", 3, 0, 3 * values["extension_bytes"]),
        *[
            (f"fri-{index}", 4, index, arity * values["extension_bytes"])
            for index, arity in enumerate(values["fri_arities"])
        ],
        ("terminal", 4, len(values["fri_arities"]), values["terminal_values"] * values["extension_bytes"]),
    ]
    zero = bytes(values["commitment_bytes"])
    return {
        "format": FIXTURE_FORMAT,
        "profile": profile["name"],
        "identity": identity_of(profile),
        "profile_frame_bytes": len(encode_profile(profile["kind"], profile["name"], profile["parameters"])),
        "inputs": inputs,
        "context_bytes": len(model.context),
        "context_sha3_256": _sha3(model.context),
        "prefix_bytes": len(model.prefix),
        "prefix_sha3_256": _sha3(model.prefix),
        "ood_answers_sha3_256": _sha3(answers),
        "rounds": rounds,
        "decoded": decoded,
        "zero_leaves": [
            {"oracle": label, "position": 0, "leaf_sha3_256": model.leaf(tag, rnd, 0, bytes(size)).hex()}
            for label, tag, rnd, size in widths
        ],
        "zero_parents": [
            {"oracle": label, "level": 1, "index": 0, "parent_sha3_256": model.parent(tag, rnd, 1, 0, zero, zero).hex()}
            for label, tag, rnd, _ in widths
        ],
    }


def transcript_profile(spec: dict[str, Any]) -> dict[str, Any]:
    """The transcript profile entry of a specification."""
    section = spec["semantic_profiles"]
    name = section["shared_transcript"]["profile"]
    for profile in section["profiles"]:
        if profile["name"] == name:
            return profile
    raise KeyError(name)


def fixture_text(spec: dict[str, Any]) -> str:
    """Canonical text of the transcript known-answer fixture of a specification."""
    transcript = spec["semantic_profiles"]["shared_transcript"]
    answers = known_answers(transcript_profile(spec), transcript["known_answers"]["inputs"])
    return json.dumps(answers, indent=1) + "\n"


def self_test() -> None:
    """Hand-written vectors for the profile frame, the CRC and the Norito frame."""
    example = [
        {"key": "queries", "type": "u64", "value": 77},
        {"key": "hash", "type": "text", "value": "FIPS202:SHA3-256"},
        {"key": "domain", "type": "bytes", "value": "00ff646f6d61696e"},
        {"key": "arities", "type": "u64-list", "value": [16, 16, 8, 8, 4]},
    ]
    encoded = encode_profile("transcript", "example.profile-v1", example)
    assert encoded.hex() == (
        "69726f68613a73656d616e7469632d70726f66696c653a763100"
        "0a0000007472616e736372697074"
        "120000006578616d706c652e70726f66696c652d7631"
        "04000000"
        "0700000071756572696573014d00000000000000"
        "04000000686173680210000000464950533230323a534841332d323536"
        "06000000646f6d61696e030800000000ff646f6d61696e"
        "07000000617269746965730405000000"
        "1000000000000000100000000000000008000000000000000800000000000000"
        "0400000000000000"
    ), "profile frame"
    assert profile_identity(encoded) == "557ef3c818f356160526fba916c44b09ab2775b824b57c79c5fe8187ae7e2349"
    assert crc64(b"123456789") == 0x995DC9BBDF1939FA, "CRC-64/XZ check value"
    first = "557ef3c818f356160526fba916c44b09ab2775b824b57c79c5fe8187ae7e2349"
    second = "3d7890a841af88bace65d95a3a7edcdbb8091b2ce94c9ecd9325fc67ea7b8467"
    assert profile_set_identity([first, second]) == "d5573da9c87a804d51f301b1dd7111ee9747aafffb3017ad86dfc2f49d4ceba9"
    assert profile_set_identity([second, first]) == "2e3fcc0b0e50ef42a224f72aaff105378a549fd8ecdec2c1289a5d1bb187363a"
    assert profile_set_identity([]) == "0c4e4fcc83e929fbdd4d60e2fe247e53f2eebe5ec755d732bc22f10813afed5b"
    assert varint(0) == b"\0" and varint(127) == b"\x7f" and varint(128) == b"\x80\x01" and varint(300) == b"\xac\x02"
    for bad in (
        ("transcript", "Upper", []),
        ("unknown", "ok", []),
        ("transcript", "ok", [{"key": "a", "type": "u64", "value": -1}]),
        ("transcript", "ok", [{"key": "a", "type": "u64", "value": True}]),
        ("transcript", "ok", [{"key": "a", "type": "bytes", "value": "AB"}]),
        ("transcript", "ok", [{"key": "a", "type": "u64", "value": 1}, {"key": "a", "type": "u64", "value": 2}]),
        ("transcript", "ok", [{"key": "a", "type": "u64", "value": 1, "note": "x"}]),
    ):
        try:
            encode_profile(*bad)
        except ProfileError:
            continue
        raise AssertionError(f"accepted {bad!r}")


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments:
        self_test()
        print("semantic profile reference: self-test passed")
        return 0
    if len(arguments) == 2 and arguments[0] in ("--print-fixture", "--write-fixture"):
        spec_path = Path(arguments[1])
        spec = json.loads(spec_path.read_text(encoding="utf-8"))
        text = fixture_text(spec)
        if arguments[0] == "--print-fixture":
            sys.stdout.write(text)
        else:
            root = Path(__file__).resolve().parents[1]
            target = root / spec["semantic_profiles"]["shared_transcript"]["known_answers"]["fixture"]
            target.write_text(text, encoding="utf-8")
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
