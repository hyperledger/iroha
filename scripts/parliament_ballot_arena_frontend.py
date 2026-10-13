#!/usr/bin/env python3
"""Ordered source allocation grammar for the standalone cold ballot frontend.

Python 3.11+, standard library only; no environment variables. Requires the
adjacent parliament_ballot_arena_backend.py for its independently reviewed
profile_trace. No verifier, build, network request or production mutation runs.
Default output is JSON on stdout; --output explicitly saves it.

Events describe pinned Rust 1.93.1 Vec/GlobalAlloc source semantics, not a
machine-code trace, stack certificate or exhaustive byte-level decoder. Caller
establishes that a chosen rejection boundary is reached. Backend rejection and
success have the same caller-owned suffix. Allocator/runtime failure, panic,
compiler allocation transformations and direct System allocation are excluded.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAX_INPUT_BYTES = 425_984
PROOF_BYTES = {("candidate", "registration"): 160_148,
               ("candidate", "vote"): 233_012,
               ("comparator", "registration"): 109_498,
               ("comparator", "vote"): 158_074}
REG_FIELDS = ("body", "network", "authority", "assignment", "governance", "election", "role")
REG_CAPS = (4096, 256, 256, 256, 256, 256, 256)
COMMON_STOPS = ("admission", "read", "record", "frame_header", "frame_body", "descriptor")
REG_STOPS = tuple(f"registration_field_{i}" for i in range(7)) + (
    "registration_fixed", "registration_digest")
VOTE_STOPS = ("vote_before_list", "vote_after_list", "vote_validation", "vote_digest")
FRONT_SOURCE_PATHS = (
    "crates/iroha_parliament_ballot_proof/examples/resource_contract/budget.rs",
    "crates/iroha_parliament_ballot_proof/examples/resource_contract/workspace.rs",
    "crates/iroha_parliament_ballot_proof/src/credential.rs",
    "crates/iroha_parliament_ballot_proof/src/framing.rs",
    "crates/iroha_parliament_ballot_proof/src/profile.rs",
    "crates/iroha_parliament_ballot_proof/src/proving.rs",
    "crates/iroha_parliament_ballot_proof/src/registration.rs",
    "crates/iroha_parliament_ballot_proof/src/sealed_list.rs",
    "crates/iroha_parliament_ballot_proof/src/test_codec.rs",
    "crates/iroha_parliament_ballot_proof/src/vote.rs",
    "rust-toolchain.toml",
)
# Source review pin, not a compiled-binary or dependency-closure certificate.
REVIEWED_SOURCE_SHA256 = "886945d9dc7d026ccc158fadcdaeb963d8de9143dc05fd77f1fd70a48cf18d18"


def source_inventory(repo: Path = ROOT) -> dict:
    """Fail closed when any directly modeled repository source has changed."""
    hashes = {name: hashlib.sha256((repo / name).read_bytes()).hexdigest()
              for name in FRONT_SOURCE_PATHS}
    digest = hashlib.sha256(json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if digest != REVIEWED_SOURCE_SHA256:
        raise ValueError("frontend allocation source changed; review before repinning")
    return {"sha256": digest, "files": hashes, "compiled_binary_binding": False}


def _profile_trace(row: str, prefix: str) -> list[dict]:
    """Delegate the two complete Profile::new invocations to their owner."""
    from parliament_ballot_arena_backend import profile_trace
    return profile_trace(row, prefix)


def trace_assumptions() -> dict:
    """Name correspondence obligations instead of treating source as execution."""
    return {
        "scope": "worker copied input through cold TEST_RECORD decoding and pre-backend preparation",
        "complete_arena_certificate": False,
        "complete_workspace_certificate": False,
        "profile_qualified": False,
        "policy": "Rust 1.93.1, 64-bit usize, default GlobalAlloc realloc allocates new before freeing old",
        "layouts": "u8 and Commitment([u8;128]) align1; borrowed slice size16 align8",
        "vec_policy": "with_capacity/to_vec/TrustedLen collect reserve exact count; extend_from_slice doubles or satisfies required capacity with minimum8 for u8",
        "drop_order": "operands reverse creation before aggregate completion; complete struct fields declaration order; locals reverse declaration",
        "drop_reference": "https://doc.rust-lang.org/reference/destructors.html#operands",
        "rejection_contract": "stop identifies an allocation-equivalent source boundary; it does not infer an error from bytes, and caller must establish reachability",
        "ordinary_invariants": "decoded immutable statement already passed first validation; repeated validation/proof-length checks cannot newly fail without source/runtime violation",
        "excluded": ["backend allocations (separate grammar)", "native stack and compiler spills",
                     "System/TLS/runtime allocations", "panic or allocation failure cleanup",
                     "compiler elimination/reordering/replacement of allocation calls"],
    }


class _Trace:
    """Emit unique allocation identities and verify source-model ownership."""

    def __init__(self) -> None:
        self.events: list[dict] = []
        self.live: dict[str, dict] = {}
        self.used: set[str] = set()

    def alloc(self, name: str, size: int, align: int, source: str) -> str | None:
        if type(size) is not int or type(align) is not int or size < 0 or align <= 0 or align & (align - 1) or name in self.used:
            raise ValueError("invalid or reused allocation")
        if size == 0:
            return None
        event = {"op": "alloc", "id": name, "size": size, "align": align, "source": source}
        self.events.append(event)
        self.live[name] = {"size": size, "align": align}
        self.used.add(name)
        return name

    def free(self, name: str | None) -> None:
        if name is not None:
            if name not in self.live:
                raise ValueError(f"free of non-live allocation: {name}")
            self.live.pop(name)
            self.events.append({"op": "free", "id": name})

    def profile(self, row: str, prefix: str) -> None:
        before = self.live.copy()
        for event in _profile_trace(row, prefix):
            if event["op"] == "alloc":
                self.alloc(event["id"], event["size"], event["align"], event["source"])
            elif event["op"] == "free":
                self.free(event["id"])
            else:
                raise ValueError("profile must provide concrete alloc/free events")
        if self.live != before:
            raise ValueError("profile retained an allocation")

    def vector(self, prefix: str, parts: tuple[int, ...], source: str) -> str | None:
        """Vec<u8>::new plus exact ordered extend_from_slice calls."""
        capacity = length = generation = 0
        current = None
        for part in parts:
            if type(part) is not int or part < 0:
                raise ValueError("negative Vec append")
            length += part
            if length > capacity:
                capacity = max(8, 2 * capacity, length)
                replacement = self.alloc(f"{prefix}.{generation}", capacity, 1, source)
                self.free(current)
                current = replacement
                generation += 1
        return current

    def frame(self, prefix: str, tag: bytes, fields: tuple[int, ...]) -> str | None:
        parts = frame_parts(tag, fields)
        return self.vector(prefix, parts, "framing.rs:frame_bytes/write_frame/Frame::{begin,field}")


def frame_parts(tag: bytes, fields: tuple[int, ...]) -> tuple[int, ...]:
    """One chunk per actual Frame Sink::absorb, including empty fields."""
    if not tag.isascii() or len(tag) > 65535 or len(fields) > 65535:
        raise ValueError("invalid frame header")
    if any(type(n) is not int or not 0 <= n < 1 << 32 for n in fields):
        raise ValueError("invalid frame field length")
    return (2, len(tag), 2) + tuple(n for size in fields for n in (4, size))


def frame_trace(tag: bytes, fields: tuple[int, ...], prefix: str = "frame") -> dict:
    """Expose a reusable exact Vec-growth trace with its returned allocation."""
    trace = _Trace()
    name = trace.frame(prefix, tag, fields)
    return {"events": trace.events, "returned": name, "retained": trace.live,
            "length": sum(frame_parts(tag, fields))}


def canonical_record_bytes(row: str, role: str, registration_lengths: tuple[int, ...] = REG_CAPS,
                           seats: int = 3) -> int:
    """Exact TEST_RECORD length for an ordinarily well-shaped statement."""
    if (row, role) not in PROOF_BYTES:
        raise ValueError("unknown row or role")
    if role == "registration":
        if len(registration_lengths) != 7 or any(type(n) is not int or not 0 <= n <= cap for n, cap in zip(registration_lengths, REG_CAPS)):
            raise ValueError("registration length out of range")
        fields = (64, *registration_lengths, 64, 128, 64)
        tag = b"PARL/TEST/REG/v1"
    else:
        if type(seats) is not int or not 3 <= seats <= 1000:
            raise ValueError("list size out of range")
        fields = (64, 64, 64, 64, 2, 128 * seats, 128, 64, 1, 64)
        tag = b"PARL/TEST/VOTE/v1"
    return 8 + PROOF_BYTES[row, role] + sum(frame_parts(tag, fields))


def frontend_trace(row: str, role: str, record_bytes: int | None = None,
                   registration_lengths: tuple[int, ...] = REG_CAPS, seats: int = 3,
                   stop: str = "backend", prefix: str = "frontend") -> dict:
    """Return prefix, backend-retained layouts and ordinary cleanup suffix.

    For stop=backend input size must be the canonical size for the supplied
    lengths. Rejection stops are abstract source boundaries: lengths describe
    successfully copied fields/list, not a complete malformed record. They
    never claim that an arbitrary byte string reaches the selected boundary.
    Error prefixes include cleanup and have no retained allocations or suffix.
    """
    canonical = canonical_record_bytes(row, role, registration_lengths, seats)
    allowed = COMMON_STOPS + (REG_STOPS if role == "registration" else VOTE_STOPS) + ("backend",)
    if stop not in allowed or not prefix:
        raise ValueError("unknown stop or empty namespace")
    length = canonical if record_bytes is None else record_bytes
    limit = (1 << 64) - 1 if stop == "admission" else MAX_INPUT_BYTES
    if type(length) is not int or not 0 <= length <= limit:
        raise ValueError("record length outside admitted copy bound")
    if stop == "backend" and length != canonical:
        raise ValueError("backend path requires canonical record length")
    t = _Trace()
    record = None
    fields = None
    typed: list[str | None] = []

    def result(suffix: list[dict] | None = None, retained: dict | None = None) -> dict:
        return {"row": row, "role": role, "stop": stop, "record_bytes": length,
                "registration_lengths": list(registration_lengths) if role == "registration" else None,
                "seats": seats if role == "vote" else None,
                "prefix": t.events, "suffix": suffix or [], "retained": retained or {},
                "reaches_backend": stop == "backend",
                "reachability_from_input_bytes_verified": False}

    def reject(order: list[str | None] | None = None) -> dict:
        for name in typed if order is None else order:
            t.free(name)
        t.free(fields)
        t.free(record)
        if t.live:
            raise ValueError("frontend rejection leaked model allocation")
        return result()

    if stop == "admission":
        return result()
    record = t.alloc(f"{prefix}.record", length, 1, "workspace.rs:execute bounded vec![0;length]")
    if stop == "read":
        return reject()
    t.profile(row, f"{prefix}.profile_decode")
    if stop in ("record", "frame_header"):
        return reject()
    fields = t.alloc(f"{prefix}.field_slices", (11 if role == "registration" else 10) * 16, 8,
                     "test_codec.rs:parse_frame Vec::with_capacity(count)")
    if stop in ("frame_body", "descriptor"):
        return reject()
    if role == "registration":
        for index, (field, size) in enumerate(zip(REG_FIELDS, registration_lengths)):
            if stop == f"registration_field_{index}":
                # A not-yet-completed context initializer drops its operand
                # temporaries in reverse creation order, then the body argument.
                return reject(list(reversed(typed)))
            typed.append(t.alloc(f"{prefix}.registration.{field}", size, 1,
                                 "test_codec.rs:decode_registration bounded BodyContext/OpaqueField::new to_vec"))
        if stop == "registration_fixed":
            # Context is now a complete argument: its fields drop in declared
            # order, then the earlier body argument. Neither reached new().
            return reject(typed[1:] + typed[:1])
        if stop == "registration_digest":
            return reject()  # Complete statement: body, then context fields.
    else:
        if stop == "vote_before_list":
            return reject()
        typed.append(t.alloc(f"{prefix}.vote.list", seats * 128, 1,
                             "test_codec.rs:decode_vote/sealed_list::split TrustedLen collect"))
        if stop in ("vote_after_list", "vote_validation"):
            return reject()
        digest = t.alloc(f"{prefix}.list_digest_decode", seats * 128, 1,
                         "VoteStatement::validate/sealed_list::digest_unvalidated concat")
        t.free(digest)
        if stop == "vote_digest":
            return reject()
    t.free(fields)
    fields = None
    if role == "vote":
        digest = t.alloc(f"{prefix}.list_digest_verify", seats * 128, 1,
                         "vote::verify repeated immutable statement.validate concat")
        t.free(digest)
    t.profile(row, f"{prefix}.profile_verify")
    public = None
    if role == "vote":
        auth = t.alloc(f"{prefix}.authorization_concat", seats * 128, 1,
                       "VoteStatement::authorization_digest concat; streamed hash")
        t.free(auth)
        public = t.alloc(f"{prefix}.public_list", seats * 128, 1,
                         "VoteStatement::instance_unvalidated VotePublic.list concat")
        frame_concat = t.alloc(f"{prefix}.frame_concat", seats * 128, 1,
                               "VoteStatement::frame concat argument temporary")
        frame = t.frame(f"{prefix}.mu_frame", b"PARL/MU/VOTE/v1",
                        (64, 64, 64, 2, seats * 128, 128, 64, 1, 64))
        t.free(frame_concat)
    else:
        frame = t.frame(f"{prefix}.mu_frame", b"PARL/MU/REG/v1", (*registration_lengths, 64, 128, 64))
    # message_digest writes mu to [u8;64] on the stack. The Frame Vec is a
    # temporary of this statement and is dropped before verify_relation.
    t.free(frame)
    retained = t.live.copy()
    before = len(t.events)
    t.free(public)
    for name in typed:
        t.free(name)
    t.free(record)
    suffix = t.events[before:]
    t.events = t.events[:before]
    if t.live:
        raise ValueError("frontend ordinary cleanup leaked model allocation")
    return result(suffix, retained)


def buddy_length_classes(maximum: int) -> tuple[tuple[int, int], ...]:
    """Exact nonnegative byte-length intervals for align1, 64-byte buddy units."""
    if type(maximum) is not int or maximum < 0:
        raise ValueError("negative length maximum")
    classes = [(0, 0)]
    low, high = 1, 64
    while low <= maximum:
        classes.append((low, min(high, maximum)))
        low, high = high + 1, high * 2
    return tuple(classes)


def registration_retained_classes():
    """Yield all 32,768 retained-layout classes, NOT full transient equivalence.

    Profile/frame temporaries must be proved safe separately for every length
    within each interval. Equal retained block orders alone do not justify
    dropping transient events or claiming exhaustive frontend sufficiency.
    """
    for ranges in itertools.product(*(buddy_length_classes(n) for n in REG_CAPS)):
        yield {"ranges": ranges, "representative_lengths": tuple(low for low, _ in ranges),
               "equivalence": "retained registration buddy orders only"}


def parameter_domain() -> dict:
    """Report finite variables without silently claiming enumerated coverage."""
    return {"copied_input_bytes": [0, MAX_INPUT_BYTES], "registration_maxima": list(REG_CAPS),
            "registration_exact_length_tuples": 4097 * 257**6,
            "registration_retained_buddy_classes": 8 * 4**6,
            "vote_seats": [3, 1000], "vote_exact_size_classes": 998,
            "stops": {"registration": list(COMMON_STOPS + REG_STOPS + ("backend",)),
                      "vote": list(COMMON_STOPS + VOTE_STOPS + ("backend",))},
            "all_frontend_transient_classes_enumerated": False}


def frontend_bounds() -> dict:
    """Bound all frontend live objects; verify the imported profile premise.

    This is the input to a separate allocator spatial lemma, not a success
    assertion. It covers partial construction and old/new realloc overlap.
    Frame growth capacity is <2*final length (or the minimum8); final F_VOTE
    <=128506 and F_REG<=5946, so every Frame block is <=262144. No frame
    allocation survives the backend handoff.
    """
    profiles = {}
    for row in ("candidate", "comparator"):
        live = {}
        count = maximum = 0
        for event in _profile_trace(row, "bounds_profile"):
            if event["op"] == "alloc":
                if event["id"] in live or event["align"] > 64:
                    raise ValueError("profile ownership/alignment premise changed")
                live[event["id"]] = event["size"]
                count = max(count, len(live))
                maximum = max(maximum, event["size"])
            elif event["op"] == "free":
                live.pop(event["id"])
            else:
                raise ValueError("profile bound requires concrete events")
        if live or count > 4 or maximum > 131072:
            raise ValueError("profile count/size premise changed")
        profiles[row] = {"peak_live_objects": count, "maximum_requested_layout": maximum}
    return {"maximum_live_objects_including_input": 12,
            "maximum_copied_input_rounded_block": 524288,
            "maximum_other_rounded_block": 262144,
            "maximum_layout_alignment": 8,
            "registration_live_count_derivation": {
                "decode": "1 record + 1 field-slice Vec + 7 typed fields = 9",
                "second_profile": "1 record + 7 typed fields + 4 profile transients = 12",
                "frame": "1 record + 7 typed fields + 2 old/new frame buffers = 10"},
            "vote_live_count_derivation": {
                "decode": "1 record + 1 field-slice Vec + 1 typed list + 1 digest concat = 4",
                "second_profile": "1 record + 1 typed list + 4 profile transients = 6",
                "frame": "1 record + 1 typed list + 1 public list + 1 concat + 2 old/new frame buffers = 6"},
            "profiles": profiles, "allocator_spatial_success_proved_here": False}


def main() -> int:
    """Emit one source-checked trace; never present it as qualification."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--row", choices=("candidate", "comparator"), default="candidate")
    parser.add_argument("--role", choices=("registration", "vote"), default="vote")
    parser.add_argument("--seats", type=int, default=1000)
    parser.add_argument("--registration-lengths", default=",".join(map(str, REG_CAPS)))
    parser.add_argument("--record-bytes", type=int)
    parser.add_argument("--stop", default="backend")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    from parliament_ballot_arena_backend import source_inventory as backend_sources, trace_assumptions as backend_assumptions
    try:
        report = {"frontend_sources": source_inventory(), "backend_sources": backend_sources(),
                  "frontend_assumptions": trace_assumptions(), "backend_assumptions": backend_assumptions(),
                  "domain": parameter_domain(), "frontend_bounds": frontend_bounds(),
                  "trace": frontend_trace(args.row, args.role, args.record_bytes,
                                          tuple(map(int, args.registration_lengths.split(","))),
                                          args.seats, args.stop)}
    except (ValueError, OSError) as error:
        parser.error(str(error))
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(text)
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
