#!/usr/bin/env python3
"""Validate the primitive and workload specification against the source tree.

Requires Python 3.9+ and its standard library; no environment variables or
installed packages are needed, and nothing is downloaded. In a Git checkout the
file list comes from `git ls-files` (tracked and unignored files); elsewhere the
tree is walked. The default specification is specs/zk_primitive_workloads.json
relative to this script's repository; it is the task H.1 output of
specs/zk_delivery_plan.md. The check is read-only. It establishes that the
specification matches the tree; it does not establish cryptographic security,
measured performance or readiness.

The check fails when
* a file in a file-granularity scan unit names a digest primitive, or one of
  its listed wrapper symbols, that the specification does not list for that
  file, or the reverse; a tree-granularity unit gains or loses a primitive; a
  scanned file belongs to no consumer;
* a (consumer, primitive) pair found by the scan is not classified under that
  consumer, a classified pair no longer occurs, or a role names a pair its
  consumer does not use;
* a digest role names a missing path, symbol or domain literal, an unknown
  primitive, family or consumer, an output length its primitive lacks, or a
  compile status (production or test-only) that the source does not show;
* a function of a ledger scope calls a digest and is not listed with its
  primitives, domain literals, return type and role, or the reverse;
* any tree file holds a pinned commitment value (as words, bytes, hexadecimal,
  decimal or base64) or names a commitment type without being listed, an
  anchored SDK owner or generated fixture disappears, or an SDK has neither an
  owner nor a recorded reason;
* a role that moves to the candidate lacks its transcript-seed check, its
  decision contradicts that check, or the lists of changing roles differ from
  the role decisions;
* the candidate frame layout, bounds or semantics differ from the pinned form
  and from the Rust reference encoder, or an example vector differs from the
  frame the specification describes (BLAKE3 is recomputed here by
  scripts/zk_blake3_reference.py, independently of the Rust crate);
* the BN254 Poseidon tables differ from the independent regeneration, a
  recorded parameter fact or defect differs from the recomputed one, a consumer
  of the helpers is unlisted, or the pinned vectors differ;
* Cargo.lock holds a post-quantum package other than the recorded ones or a
  superseded pre-standard package, a known-answer response file does not hash
  to its official digest, a call site or a legacy algorithm label is unlisted,
  a required finding is missing, or a named test no longer exists;
* a workload lacks an identity, a shape, a measured quantity or a phase label,
  uses a label outside the grammar of crates/iroha_measurement/src/text.rs,
  names an unknown backend consumer, measures State candidates (owned by G.2),
  or records a measurement that is not labelled exploratory;
* a shared transcript requirement loses its order, its binding list or a
  current implementation site, or the listed engines differ from those of
  specs/fastpq/shared_backend_inventory.json;
* a frozen or retained semantic profile (task H.2) records an identity other
  than the SHA3-256 of its canonical frame, recomputed here by
  scripts/zk_semantic_profile_reference.py; a retained profile differs from its
  role record; a digest role has no disposition, or the unqualified six-lane
  digest is retained or frozen; an H.1 defect has no disposition; a corrected
  BN254 table, the native commitment frame or a post-quantum parameter set
  differs from what its profile froze; the frozen transcript loses a binding
  entry, a named test, a golden pin, an engine or its known answers, or its
  security statement stops recording the classical claim as conditional and
  the quantum claim as open;
* a workload does not name the profiles of its roles, or a workload measurement
  omits any profile identity, changes its section's measurement scope, or names
  a profile identity other than the current one: such a
  measurement is inapplicable and the check fails until it is re-measured or
  moved to the inapplicable list. No approval or runtime switch is involved.

Limits of the check
* Primitives are found by name and by the wrapper symbols the specification
  lists. A digest reached through an unlisted re-export, a macro expansion or a
  foreign-language binding without the algorithm name is invisible. Shell
  scripts, manifests, Markdown and data files are not scanned for primitives
  (they are scanned for pinned values).
* Inside a tree-granularity unit a new file that uses an already listed
  primitive is not reported.
* A role site is anchored by text. The check shows that the named symbol and
  literals are present, not that the described construction is implemented.
* The producer ledger is lexical (see scripts/zk_rust_lexical_index.py): it
  lists functions whose own body names a digest call, inside the declared
  scopes only. A caller that only forwards to such a function is not listed.
  Explicit included-domain bindings additionally validate direct unconditional
  file-scope includes and byte-string constants; they do not resolve arbitrary
  imports, cfg predicates, macros or cryptographic dataflow. Invalid bindings
  also refuse refresh/write, preserving the recorded evidence.

Maintainer modes (the default run changes nothing)
* `--print-scan` prints the fresh scan as JSON.
* `--refresh` prints the specification with every derived table recomputed
  from the tree: scan tables, pinned-value carriers, type files, producer
  facts, BN254 helper consumers, post-quantum call sites and legacy labels,
  and the derived tables of the semantic profiles: the retained profile and
  identity of each retained role and each workload's profile lists.
  Classifications, roles, role assignments, frozen profiles and the identities
  that measurements name are never changed, so a new use still fails until a
  maintainer classifies it and a changed identity leaves its measurements
  inapplicable.
* `--refresh --write` writes that result over the specification file.
* `--write-candidate-vectors` rewrites the candidate frame fixture from the
  specification, with all three digest columns recomputed here.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import posixpath
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
from typing import Any, Iterator, Optional, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))

import zk_blake3_reference as blake3_reference  # noqa: E402
import zk_bn254_poseidon_reference as poseidon_reference  # noqa: E402
import zk_pq_kat_reference as pq_reference  # noqa: E402
import zk_rust_lexical_index as rust_index  # noqa: E402
import zk_semantic_profile_reference as profile_reference  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SPEC = "specs/zk_primitive_workloads.json"
SCHEMA_VERSION = 2
SCOPE = "Specification consistency only; not cryptographic qualification or measured performance."
SKIP_DIRECTORIES = frozenset(
    {".git", "target", "dist", "node_modules", "build", ".build", ".gradle", "DerivedData"}
)
# Files above this size are not read; the check fails unless each is listed.
MAX_FILE_BYTES = 64 * 1024 * 1024
ROLE_KEY = re.compile(r"[a-z0-9]+(?:[.-][a-z0-9]+)*\Z")
USE_CLASSES = frozenset(
    {
        "role",
        "ledger-identity",
        "proof-internal",
        "in-circuit",
        "standard-internal",
        "kdf-or-mac",
        "commitment-scheme",
        "evidence-metadata",
        "transport-or-storage",
        "label-only",
        "test-or-tooling",
    }
)
PRIMITIVE_KINDS = frozenset(
    {"native", "algebraic", "commitment", "kdf-mac", "password-kdf", "wrapper", "watch"}
)
# Role family -> primitive kinds that can serve it.
ROLE_FAMILIES = {
    "native": frozenset({"native", "algebraic", "commitment", "wrapper"}),
    "in-circuit": frozenset({"native", "algebraic", "commitment", "wrapper"}),
    "proof-internal": frozenset({"native", "algebraic", "commitment"}),
    "standard-internal": frozenset({"native", "commitment"}),
    "kdf": frozenset({"kdf-mac", "password-kdf", "native"}),
}
# Canonical-native decision -> role families it can apply to.
NATIVE_DECISIONS = {
    "changes": frozenset({"native"}),
    "changes-with-profile": frozenset({"native"}),
    "provisional": frozenset({"native"}),
    "already-blake3": frozenset({"native"}),
    "proof-internal": frozenset({"proof-internal", "in-circuit"}),
    "retained-family": frozenset(ROLE_FAMILIES),
    "standard-internal": frozenset({"standard-internal", "in-circuit"}),
    "not-a-commitment": frozenset({"kdf"}),
}
# Decisions under which a role moves to the candidate frame; each carries a
# transcript-seed check, and a role whose value binds proof internals moves
# only together with the proof profile.
MOVING_DECISIONS = ("changes", "changes-with-profile", "provisional", "already-blake3")
# The consumers the H.1 acceptance names; each needs a role that moves or a
# recorded reading of why none does.
REQUIRED_CONSUMERS = ("privacy-catalog", "kaigi", "confidential", "mkhe")
REQUIRED_BN254_DEFECTS = ("BN254-POSEIDON-D1", "BN254-POSEIDON-D2", "BN254-POSEIDON-D3")
REQUIRED_PQ_FINDINGS = ("PQ-D1", "PQ-D2", "PQ-D3")
SDKS = ("rust", "swift", "kotlin", "javascript", "python", "csharp")
SDK_PATH_ROOTS = {
    "swift": ("IrohaSwift/",),
    "kotlin": ("kotlin/", "java/"),
    "javascript": ("javascript/",),
    "python": ("python/",),
    "csharp": ("csharp/",),
}
SUPERSEDED_PQ_PACKAGES = re.compile(
    r"(?:\A|[-_])(?:kyber|dilithium|sphincs|saber|ntru|frodo|sike|rainbow|picnic|newhope)"
    r"(?:\Z|[-_0-9])|pqcrypto-(?!internals\Z|traits\Z|mlkem\Z|mldsa\Z)"
)
PQ_PACKAGE = re.compile(r"pqcrypto|ml-?kem|ml-?dsa|fips20[3-5]|slh-?dsa|falcon|fn-?dsa|oqs|pqclean")
LEGACY_PQ_LABEL = re.compile(r"kyber|dilithium")
PQ_CALL_SITE = re.compile(r"pqcrypto_(?:mlkem|mldsa|traits)|soranet_pq")
SDK_MANIFEST = re.compile(
    r"(?:build\.gradle(?:\.kts)?|settings\.gradle(?:\.kts)?|libs\.versions\.toml|Package\.swift|"
    r"package\.json|pyproject\.toml|requirements[^/]*\.txt|[^/]+\.csproj)\Z"
)
SDK_ROOTS = ("kotlin/", "java/", "IrohaSwift/", "javascript/", "python/", "csharp/")
SDK_PQ_LIBRARY = re.compile(r"liboqs|pqclean|pqcrypto|kyber|dilithium|bcpqc", re.I)
JVM_SOURCE = (".kt", ".kts", ".java")
BOUNCYCASTLE_PQ = re.compile(
    r"org\.bouncycastle\.pqc|org\.bouncycastle\.[\w.]*(?:kyber|dilithium|mldsa|mlkem)", re.I
)
LABEL_GRAMMAR_SOURCE = "crates/iroha_measurement/src/text.rs"
# The canonical frame, version 1. The specification states this layout; the
# check fails when the two differ, so neither can change alone.
FRAME_LAYOUT_V1 = (
    ("magic", None, "magic"),
    ("algorithm", 1, "bytes-u32-le"),
    ("catalog", 2, "bytes-u32-le"),
    ("protocol", 3, "bytes-u32-le"),
    ("profile", 4, "bytes-u32-le"),
    ("role", 5, "bytes-u32-le"),
    ("phase", 6, "bytes-u32-le"),
    ("level", 7, "u64-le"),
    ("index", 8, "u64-le"),
    ("counter", 9, "u64-le"),
    ("field_count", 10, "count-u32-le"),
    ("fields", 11, "each-bytes-u64-le"),
)
FRAME_BOUND_CONSTANTS = {
    "domain_field_max_bytes": "MAX_DOMAIN_FIELD_BYTES_V1",
    "payload_field_count_max": "MAX_PAYLOAD_FIELDS_V1",
}
# Words that mark a State tree or hash workload; G.2 owns those.
STATE_WORKLOAD = re.compile(r"state[-_ ](?:tree|commitment|root|candidate)|keyed[-_ ]state|\bwg\b", re.I)
# Pairs of examples the frame semantics require to differ, by example name.
FRAME_DISTINCT_EXAMPLES = (
    ("split-abc-def", "joined-abcdef"),
    ("no-fields", "one-empty-field"),
    ("kaigi-call-id", "kaigi-account-id"),
    ("spentness-leaf", "spentness-node"),
)
# Column of the first payload field in an `example` row of the candidate
# fixture; the column before it holds the field count.
EXAMPLE_FIELDS_AT = 12
_UPPER = frozenset(range(ord("A"), ord("Z") + 1))
_LOWER_OR_DIGIT = frozenset(range(ord("a"), ord("z") + 1)) | frozenset(range(ord("0"), ord("9") + 1))
_IDENTIFIER_BYTES = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_")
_STRING_CONSTANT = re.compile(
    r'\b(?:const|static)\s+([A-Z][A-Z0-9_]*)\s*:\s*[^=;]*=\s*b?r?#*"((?:[^"\\]|\\.)*)"'
)
_INLINE_LITERAL = re.compile(r'\bb"((?:[^"\\]|\\.)*)"')
_CONSTANT_NAME = re.compile(r"\b[A-Z][A-Z0-9_]{2,}\b")
_DOMAIN_LITERAL = re.compile(r"[ -~]{6,160}\Z")


# ---------------------------------------------------------------------------
# Tree access
# ---------------------------------------------------------------------------


def tree_files(root: Path) -> list[str]:
    """Tracked and unignored files, or a walk when `root` is not a Git checkout."""
    try:
        listed = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            cwd=root,
            capture_output=True,
            check=True,
        ).stdout.decode("utf-8", "surrogateescape")
        inside = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"], cwd=root, capture_output=True, check=True
        ).stdout.decode().strip()
        if Path(inside).resolve() == root.resolve():
            return sorted(path for path in listed.split("\0") if path and (root / path).is_file())
    except (OSError, subprocess.CalledProcessError):
        pass
    found = []
    for directory, names, files in os.walk(root):
        names[:] = sorted(name for name in names if name not in SKIP_DIRECTORIES)
        for name in files:
            found.append(Path(directory, name).relative_to(root).as_posix())
    return sorted(found)


def read_text(root: Path, path: str) -> str:
    """Read a tree file as text; undecodable bytes are replaced."""
    return (root / path).read_text(encoding="utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Digest scan
# ---------------------------------------------------------------------------


def literal_starts(pattern: str) -> list[str]:
    """Literal text that every match of each top-level alternative begins with.

    An empty string means that alternative has no literal start; the caller
    then searches with the pattern alone.
    """
    alternatives, depth, current, escaped, in_class = [], 0, [], False, False
    for char in pattern:
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif in_class:
            in_class = char != "]"
        elif char == "[":
            in_class = True
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "|" and depth == 0:
            alternatives.append("".join(current))
            current = []
            continue
        current.append(char)
    alternatives.append("".join(current))
    starts = []
    for alternative in alternatives:
        match = re.match(r"[A-Za-z0-9_:<> -]*", alternative)
        literal = match.group(0) if match else ""
        # A quantifier makes the character before it optional or repeated.
        if alternative[len(literal):len(literal) + 1] in ("?", "*", "{"):
            literal = literal[:-1]
        starts.append(literal)
    return starts


class _Finder:
    """A pattern searched from the occurrences of its literal starts."""

    def __init__(self, pattern: str, text: str) -> None:
        self.pattern = re.compile(pattern.encode("ascii"))
        starts = sorted(set(literal_starts(text)))
        # One alternative with a literal start is searched fastest by the pattern itself.
        direct = len(starts) == 1 or "" in starts
        self.starts = None if direct else [start.encode("ascii") for start in starts]

    def positions(self, data: bytes) -> Iterator[int]:
        """Start offsets of the matches of the pattern in `data`."""
        if self.starts is None:
            for match in self.pattern.finditer(data):
                yield match.start()
            return
        for start in self.starts:
            position = data.find(start)
            while position >= 0:
                if self.pattern.match(data, position):
                    yield position
                position = data.find(start, position + 1)

    def occurs(self, data: bytes) -> bool:
        """Whether the pattern matches anywhere in `data`."""
        return next(self.positions(data), None) is not None


class Token:
    """How one primitive is recognised in a file."""

    def __init__(self, token: dict[str, Any]) -> None:
        self.finder = _Finder(token["pattern"], token["pattern"])
        self.forbidden = frozenset(token.get("not_preceded_by", "").encode("ascii"))
        self.camel_case = bool(token.get("camel_case"))
        self.wrappers = [
            (
                _Finder(f"(?:{wrapper['symbol']})(?![A-Za-z0-9_])", wrapper["symbol"]),
                re.compile(wrapper["paths"]) if wrapper.get("paths") else None,
            )
            for wrapper in token.get("wrappers", [])
        ]

    def names(self, data: bytes, lowered: bytes) -> bool:
        """Whether the algorithm name occurs at an accepted position."""
        for start in self.finder.positions(lowered):
            if not self.forbidden or start == 0:
                return True
            previous = data[start - 1]
            if lowered[start - 1] not in self.forbidden:
                return True
            # A CamelCase word boundary: `MerkleSm3`, `KeyedHmac`.
            if self.camel_case and data[start] in _UPPER and previous in _LOWER_OR_DIGIT:
                return True
        return False

    def wrapped(self, data: bytes, path: str) -> bool:
        """Whether a wrapper symbol of the primitive occurs in a file at `path`."""
        for finder, paths in self.wrappers:
            if paths is not None and not paths.search(path):
                continue
            for start in finder.positions(data):
                if start == 0 or data[start - 1] not in _IDENTIFIER_BYTES:
                    return True
        return False


class Scanner:
    """Name-based digest scan driven by the specification."""

    def __init__(self, spec: dict[str, Any]) -> None:
        scan = spec["scan"]
        self.extensions = tuple(scan["extensions"])
        self.tokens = {
            primitive["id"]: Token(primitive["token"]) for primitive in spec["digest_primitives"]
        }
        self.excluded = frozenset(scan.get("exclude_files", []))
        scope = scan["scope"]
        self.full_prefixes = tuple(scope["file_granularity_prefixes"])
        self.word_roots = tuple(scope["file_granularity_path_roots"])
        self.words = re.compile(scope["file_granularity_path_pattern"])
        self.content = frozenset(scope["file_granularity_primitives"])
        self.tree_overrides = [
            (re.compile(entry["pattern"]), entry["unit"], bool(entry.get("inside_proof_crates")))
            for entry in scope["tree_unit_overrides"]
        ]
        self.rules = [
            (re.compile(rule["pattern"]), rule["consumer"]) for rule in scan["consumer_rules"]
        ]

    def primitives_in(self, data: bytes | str, path: str = "") -> list[str]:
        """Primitive ids named in a file's bytes, by algorithm name or wrapper symbol."""
        if isinstance(data, str):
            data = data.encode("utf-8", "surrogateescape")
        lowered = data.lower()
        return sorted(
            name
            for name, token in self.tokens.items()
            if token.names(data, lowered) or token.wrapped(data, path)
        )

    def unit_of(self, path: str, found: Sequence[str] = ()) -> tuple[str, str]:
        """Return (unit key, granularity) of a scanned path that names `found`."""
        low = path.lower()
        in_proof_crate = path.startswith(self.full_prefixes)
        for pattern, unit, inside in self.tree_overrides:
            if pattern.search(low) and (inside or not in_proof_crate):
                return unit, "tree"
        parts = path.split("/")
        package = "/".join(parts[:2]) if parts[0] == "crates" and len(parts) > 2 else parts[0]
        if in_proof_crate or (
            path.startswith(self.word_roots)
            and (self.words.search(low) or not self.content.isdisjoint(found))
        ):
            return package + "#zk", "file"
        return package + "#other", "tree"

    def consumer_of(self, path: str) -> str | None:
        """Consumer key of a file-granularity path; first matching rule wins."""
        low = path.lower()
        for pattern, consumer in self.rules:
            if pattern.search(low):
                return consumer
        return None

    def scan(self, root: Path, files: Sequence[str]) -> dict[str, Any]:
        """Scan the tree into file-granularity and tree-granularity tables."""
        file_table: dict[str, list[str]] = {}
        tree_table: dict[str, set[str]] = {}
        for path in files:
            if self.scans(path):
                self.record(path, (root / path).read_bytes(), file_table, tree_table)
        return self.tables(file_table, tree_table)

    def scans(self, path: str) -> bool:
        """Whether the digest scan reads this path."""
        return path.endswith(self.extensions) and path not in self.excluded

    def record(
        self, path: str, data: bytes, file_table: dict[str, list[str]], tree_table: dict[str, set[str]]
    ) -> None:
        """Add the primitives of one file to the scan tables."""
        found = self.primitives_in(data, path)
        if not found:
            return
        unit, granularity = self.unit_of(path, found)
        if granularity == "file":
            file_table[path] = found
        else:
            tree_table.setdefault(unit, set()).update(found)

    @staticmethod
    def tables(file_table: dict[str, list[str]], tree_table: dict[str, set[str]]) -> dict[str, Any]:
        """Sorted scan tables."""
        return {
            "files": dict(sorted(file_table.items())),
            "tree_units": {unit: sorted(found) for unit, found in sorted(tree_table.items())},
        }


# ---------------------------------------------------------------------------
# Pinned values and commitment surfaces
# ---------------------------------------------------------------------------


def pinned_needles(pinned: dict[str, Any]) -> dict[str, list[bytes]]:
    """Byte strings that carry a pinned value, by form name.

    `words` are the 64-bit words of the value in order; the value's bytes are
    the little-endian words concatenated. A file is a carrier when it holds the
    first word as hexadecimal (either byte order, optionally grouped by `_`) or
    as a decimal number, or the whole value as raw bytes, hexadecimal, a comma-
    separated hexadecimal byte array (including Kotlin `toByte()`), or base64
    at any of the three byte alignments. The array needle is a regular expression.
    """
    words = [int(word, 16) for word in pinned["words"]]
    raw = b"".join(word.to_bytes(8, "little") for word in words)
    first = f"{words[0]:016x}"
    grouped = "_".join(first[index:index + 4] for index in range(0, 16, 4))
    reversed_first = raw[:8].hex()
    encoded = []
    for pad in range(3):
        for alphabet in (base64.b64encode, base64.urlsafe_b64encode):
            text = alphabet(b"\0" * pad + raw).decode("ascii")
            # Drop the characters that depend on neighbouring bytes.
            encoded.append(text[(4 if pad else 0):-4].encode("ascii"))
    return {
        "word-hex": [form.encode("ascii") for form in (first, first.upper(), grouped, grouped.upper())],
        "word-hex-reversed": [reversed_first.encode("ascii"), reversed_first.upper().encode("ascii")],
        "word-decimal": [str(words[0]).encode("ascii")],
        "bytes-hex": [raw.hex().encode("ascii"), raw.hex().upper().encode("ascii")],
        "bytes-raw": [raw],
        "bytes-base64": sorted(set(encoded)),
        "bytes-array": [
            rb"(?:^|[\[(,])\s*"
            + rb"\s*,\s*".join(
                f"0x{byte:02x}".encode("ascii") + rb"(?:\s*\.toByte\(\))?" for byte in raw
            )
            + rb"(?=\s*[,\])])"
        ],
    }


def carrier_forms(data: bytes, needles: dict[str, list[bytes]]) -> list[str]:
    """Names of the pinned-value forms a file holds."""
    found = []
    for form, values in needles.items():
        if form == "bytes-array":
            if any(re.search(value, data, re.I) for value in values):
                found.append(form)
        elif form == "word-decimal":
            if any(_whole_number(data, value) for value in values):
                found.append(form)
        elif any(value in data for value in values):
            found.append(form)
    return found


def _whole_number(data: bytes, digits: bytes) -> bool:
    """Whether `digits` occurs in `data` without a digit on either side."""
    position = data.find(digits)
    while position >= 0:
        end = position + len(digits)
        before = data[position - 1:position] if position else b""
        if not before.isdigit() and not data[end:end + 1].isdigit():
            return True
        position = data.find(digits, position + 1)
    return False


class Surface:
    """Files that name the type of one commitment role."""

    def __init__(self, surface: dict[str, Any]) -> None:
        self.tokens = [_Finder(token, token) for token in surface["type_tokens"]]
        self.extensions = tuple(surface["extensions"])
        self.excluded = tuple(surface.get("exclude_prefixes", []))

    def reads(self, path: str) -> bool:
        """Whether the surface scan reads this path."""
        return path.endswith(self.extensions) and not path.startswith(self.excluded)

    def names(self, data: bytes) -> bool:
        """Whether a type token occurs in a file's bytes."""
        return any(token.occurs(data) for token in self.tokens)


# ---------------------------------------------------------------------------
# Producer ledger
# ---------------------------------------------------------------------------


class ProducerLedger:
    """Functions of the declared scopes whose body calls a digest."""

    def __init__(self, ledger: dict[str, Any]) -> None:
        self.detectors = {
            primitive: re.compile(pattern) for primitive, pattern in ledger["detectors"].items()
        }
        self.scopes = [(scope["crate"], tuple(scope["prefixes"])) for scope in ledger["scopes"]]
        self.domain_bindings = json.loads(json.dumps(ledger.get("included_domain_bindings", [])))

    def crates(self) -> list[str]:
        return sorted({crate for crate, _ in self.scopes})

    def in_scope(self, path: str) -> bool:
        return path.endswith(".rs") and any(path.startswith(prefixes) for _, prefixes in self.scopes)

    def derive(self, root: Path, files: Sequence[str]) -> dict[str, Any]:
        """Production producers per file, and counts of test-only and unreached ones."""
        production: dict[str, dict[str, Any]] = {}
        test_only: dict[str, int] = {}
        unreached: list[str] = []
        cache: dict[str, Optional[str]] = {}

        def read(path: str) -> Optional[str]:
            if path not in cache:
                try:
                    cache[path] = (root / path).read_text(encoding="utf-8", errors="replace")
                except OSError:
                    cache[path] = None
            return cache[path]

        for crate in self.crates():
            members = [path for path in files if path.startswith(crate) and path.endswith(".rs")]
            modules = rust_index.CrateModules(members, read)
            for path in members:
                if not self.in_scope(path):
                    continue
                source = read(path)
                if source is None or not any(d.search(source) for d in self.detectors.values()):
                    continue
                status = modules.status(path)
                constants = dict(_STRING_CONSTANT.findall(source))
                masked = rust_index.mask(source)
                functions = rust_index.functions(source, masked)
                for function in functions:
                    # A nested function is listed on its own; its text does not
                    # make the enclosing function a producer.
                    body = _own_body(source, function, functions)
                    used = sorted(name for name, rx in self.detectors.items() if rx.search(body))
                    if not used:
                        continue
                    if status == "unreached":
                        if path not in unreached:
                            unreached.append(path)
                        continue
                    if status != "production" or function.test_only():
                        test_only[path] = test_only.get(path, 0) + 1
                        continue
                    entry = {
                        "primitives": used,
                        "domains": _domains(body, constants),
                        "returns": function.returns,
                    }
                    name = function.qualified_name()
                    listed = production.setdefault(path, {})
                    # Two impl blocks of one type can hold functions of the same name.
                    key, suffix = name, 2
                    while key in listed:
                        key, suffix = f"{name}#{suffix}", suffix + 1
                    listed[key] = entry
        binding_errors = []
        seen_bindings = set()
        bindings = self.domain_bindings
        if not isinstance(bindings, list):
            binding_errors.append("included-domain bindings must be a list")
            bindings = []
        for binding in bindings:
            try:
                path, name, symbol = binding["path"], binding["producer"], binding["symbol"]
                key = (path, name, symbol)
                if key in seen_bindings:
                    raise ValueError("duplicate included-domain binding")
                seen_bindings.add(key)
                if name not in production.get(path, {}):
                    raise ValueError("bound producer is absent from production")
                crate = next(crate for crate in self.crates() if path.startswith(crate))
                members = [member for member in files if member.startswith(crate) and member.endswith(".rs")]
                literal = _included_domain(binding, members, read)
                entry = production[path][name]
                entry["domains"] = sorted(set(entry["domains"]) | {literal})
            except (KeyError, TypeError, ValueError, StopIteration) as error:
                binding_errors.append(f"included-domain binding {binding!r}: {error}")
        return {
            "domain_bindings": json.loads(json.dumps(self.domain_bindings)),
            "binding_errors": binding_errors,
            "production": dict(sorted(production.items())),
            "test_only_counts": dict(sorted(test_only.items())),
            "unreached_files": sorted(unreached),
        }


def _unconditional_top_level(source: str, position: int) -> bool:
    """Whether an item is at file scope without an attribute on that item.

    Explicit bindings deliberately support only unconditional direct items;
    this is not cfg evaluation or Rust name resolution.
    """
    masked = rust_index.mask(source)
    if any(block.body_start < position < block.end for block in rust_index.blocks(source, masked)):
        return False
    start, depth = 0, 0
    for offset, char in enumerate(masked[:position]):
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
            if char == "}" and depth == 0:
                start = offset + 1
        elif char == ";" and depth == 0:
            start = offset + 1
    return depth == 0 and not re.search(r"#\s*!?\s*\[", masked[start:position])


def _direct_includes(path: str, source: str) -> list[tuple[str, bool]]:
    """Literal targets, including alternate syntax for ambiguity detection.

    Only plain parenthesized, non-traversing, unconditional file-scope includes
    are eligible defining splices. Raw/braced/commented/traversing alternatives
    still count as competing owners. Escaped strings and macro-computed paths
    are refused rather than silently omitted from ownership accounting.
    """
    masked = rust_index.mask(source)
    result = []
    for match in re.finditer(r"\binclude\s*!\s*([({\[])", masked):
        start = match.end()
        while start < len(masked) and masked[start].isspace():
            start += 1
        opening = re.match(r'(?:r(?P<hashes>#{0,}))?"', source[start:])
        if opening is None:
            raise ValueError("include path must be a direct unescaped string literal")
        hashes = opening.group("hashes")
        begin = start + opening.end()
        end = source.find('"' + (hashes or ""), begin)
        if end < 0:
            raise ValueError("unterminated include path literal")
        literal = source[begin:end]
        if hashes is None and "\\" in literal:
            raise ValueError("escaped include paths are unsupported in a bound crate")
        tail = end + 1 + len(hashes or "")
        while tail < len(masked) and masked[tail].isspace():
            tail += 1
        if tail >= len(masked) or masked[tail] != {"(": ")", "{": "}", "[": "]"}[match.group(1)]:
            raise ValueError("include argument is not one literal path")
        tail += 1
        while tail < len(masked) and masked[tail].isspace():
            tail += 1
        if masked[tail:tail + 1] == ";":
            tail += 1
        target = PurePosixPath(path).parent / literal
        canonical = re.fullmatch(r'include\s*!\s*\(\s*"[^"\\]+"\s*\)\s*;', source[match.start():tail])
        eligible = bool(canonical) and not target.is_absolute() and ".." not in target.parts
        result.append((posixpath.normpath(target.as_posix()), eligible and _unconditional_top_level(source, match.start())))
    return result


def _included_domain(binding: dict[str, str], files: Sequence[str], read) -> str:
    """Validate one explicit direct-include domain binding and return its literal.

    Require unique include ownership, one unconditional top-level byte-string
    constant, and one unqualified update argument in the producer's own body.
    Refuse shadowing declarations/imports and ambiguous sibling definitions.
    Comments, strings, nested helpers and unrelated modules cannot supply use
    evidence. Macro expansion and general Rust name resolution remain outside
    this lexical check. Absolute literal includes anywhere in a bound crate
    are refused because they cannot provide portable source ownership.
    """
    if not isinstance(binding, dict) or set(binding) != {"path", "producer", "owner", "symbol", "literal"}:
        raise ValueError("expected path, producer, owner, symbol and literal")
    if not all(isinstance(value, str) and value for value in binding.values()):
        raise ValueError("binding values must be nonempty strings")
    path, owner, symbol, literal = (binding[key] for key in ("path", "owner", "symbol", "literal"))
    if not re.fullmatch(r"[A-Z][A-Z0-9_]*", symbol) or not _DOMAIN_LITERAL.fullmatch(literal):
        raise ValueError("invalid symbol or printable domain literal")
    if path == owner or path not in files or owner not in files:
        raise ValueError("producer and defining owner must be distinct files in the same crate")
    modules = rust_index.CrateModules(files, read)
    if modules.status(owner) != "production":
        raise ValueError("defining owner is not a production module")
    incoming = []
    include_map = {}
    for candidate in files:
        source = read(candidate)
        if source is None:
            continue
        includes = _direct_includes(candidate, source)
        if any(PurePosixPath(target).is_absolute() for target, _ in includes):
            raise ValueError("absolute include paths are unsupported in a bound crate")
        incoming.extend((candidate, unconditional) for target, unconditional in includes if target == path)
        include_map[candidate] = [target for target, _ in includes]
    if incoming != [(owner, True)]:
        raise ValueError("expected one unconditional top-level include from the defining owner")
    owner_source = read(owner)
    source = read(path)
    if owner_source is None or source is None:
        raise ValueError("binding source is missing")
    declaration = re.compile(rf"\b(?:const|static)\s+{re.escape(symbol)}\b")
    # Included siblings can themselves include a colliding definition. Follow
    # the entire literal splice family conservatively, including guarded ones.
    family, pending = set(), [owner]
    while pending:
        member = pending.pop()
        if member not in files:
            raise ValueError("included splice family leaves the indexed Rust files")
        if member not in family:
            family.add(member)
            pending.extend(include_map.get(member, []))
    definitions = []
    for member in sorted(family):
        text = read(member)
        if text is None:
            raise ValueError("included sibling source is missing")
        masked = rust_index.mask(text)
        definitions.extend((member, match.start()) for match in declaration.finditer(masked))
        # Imports can shadow the explicit constant. Only relevant file-scope
        # imports are considered; ordinary test-module `use super::*` is fine.
        for use in re.finditer(r"\buse\s+[^;]+;", masked):
            if re.search(rf"\b{re.escape(symbol)}\b", use.group()) and not any(
                block.body_start < use.start() < block.end for block in rust_index.blocks(text, masked)
            ):
                raise ValueError("ambiguous imported domain symbol")
    if len(definitions) != 1 or definitions[0][0] != owner:
        raise ValueError("expected one domain constant in its defining owner, without shadowing")
    position = definitions[0][1]
    if not _unconditional_top_level(owner_source, position):
        raise ValueError("domain constant must be unconditional top-level")
    constant = re.match(rf'const\s+{re.escape(symbol)}\s*:\s*&\s*\[\s*u8\s*\]\s*=\s*b"([^"\\]*)"\s*;', owner_source[position:])
    if constant is None or constant.group(1) != literal:
        raise ValueError("domain literal differs from its byte-string constant")
    functions = rust_index.functions(source)
    matching = [function for function in functions if function.qualified_name() == binding["producer"]]
    if len(matching) != 1 or matching[0].test_only():
        raise ValueError("expected one production function for the bound producer")
    for parent in matching[0].chain()[1:]:
        header = rust_index.mask(source[parent.header_start:parent.body_start])
        if parent.kind != "impl" or re.search(rf"\b{re.escape(symbol)}\b", header):
            raise ValueError("unsupported or shadowing producer scope")
    body = rust_index.mask(_own_body(source, matching[0], functions))
    if re.search(r"\buse\s+[^;]*\*[^;]*;", body):
        raise ValueError("ambiguous local glob import")
    occurrences = list(re.finditer(rf"\b{re.escape(symbol)}\b", body))
    argument = re.search(
        rf"\b[A-Za-z_][A-Za-z0-9_]*\s*\.\s*update\s*\(\s*{re.escape(symbol)}\s*\)\s*;", body
    )
    if len(occurrences) != 1 or argument is None:
        raise ValueError("producer must use the unshadowed symbol once as a direct update argument")
    start, delimiters = 0, []
    for offset, char in enumerate(body[:argument.start()]):
        if char in "([{":
            delimiters.append(char)
            if delimiters == ["{"]:
                start = offset + 1
        elif char in ")]}":
            if not delimiters or delimiters.pop() != {")": "(", "]": "[", "}": "{"}[char]:
                raise ValueError("unbalanced producer delimiters")
        elif char == ";" and delimiters == ["{"]:
            start = offset + 1
    if delimiters != ["{"] or body[start:argument.start()].strip():
        raise ValueError("domain update must be a direct function-body statement")
    return literal


def _own_body(source: str, function: rust_index.Block, functions: Sequence[rust_index.Block]) -> str:
    """Text of a function without the text of functions nested inside it."""
    pieces, position = [], function.header_start
    for nested in functions:
        if nested is not function and function.body_start < nested.header_start and nested.end <= function.end:
            if nested.header_start >= position:
                pieces.append(source[position:nested.header_start])
                position = nested.end
    pieces.append(source[position:function.end])
    return "".join(pieces)


def _domains(body: str, constants: dict[str, str]) -> list[str]:
    """Domain literals a function body names, as written in the source.

    These are its inline byte-string literals and the string or byte-string
    constants of its file that it names. Only printable literals of six to 160
    characters are kept.
    """
    found = set(_INLINE_LITERAL.findall(body))
    found |= {constants[name] for name in _CONSTANT_NAME.findall(body) if name in constants}
    return sorted(literal for literal in found if _DOMAIN_LITERAL.match(literal))


# ---------------------------------------------------------------------------
# Candidate frame
# ---------------------------------------------------------------------------


def encode_candidate_frame(example: dict[str, Any], frame: dict[str, Any]) -> bytes:
    """Encode one example with the layout and bounds the specification states.

    Raises `ValueError` for an unknown layout entry or a value outside the
    stated bounds.
    """
    bounds = frame["bounds"]
    out = bytearray()
    fields = [bytes.fromhex(field) for field in example["fields_hex"]]
    for entry in sorted(frame["layout"], key=lambda item: item["order"]):
        name, kind = entry["field"], entry["kind"]
        tag = bytes([entry["tag"]]) if entry.get("tag") is not None else b""
        if kind == "magic":
            out += frame["magic_ascii"].encode("ascii") + b"\0"
        elif kind == "bytes-u32-le":
            data = example[name].encode("ascii")
            if len(data) > bounds["domain_field_max_bytes"]:
                raise ValueError(f"{name} exceeds the domain field bound")
            out += tag + len(data).to_bytes(4, "little") + data
        elif kind == "u64-le":
            out += tag + int(example[name]).to_bytes(8, "little")
        elif kind == "count-u32-le":
            if len(fields) > bounds["payload_field_count_max"]:
                raise ValueError("payload field count exceeds its bound")
            out += tag + len(fields).to_bytes(4, "little")
        elif kind == "each-bytes-u64-le":
            for field in fields:
                if len(field) > bounds["payload_field_max_bytes"]:
                    raise ValueError("payload field exceeds its bound")
                out += tag + len(field).to_bytes(8, "little") + field
        else:
            raise ValueError(f"unknown frame layout kind {kind!r}")
    return bytes(out)


def render_candidate_vectors(spec: dict[str, Any]) -> str:
    """Render the candidate fixture with every digest column recomputed here."""
    frame_spec = spec["canonical_native_commitment"]["frame"]
    lines = [
        "# Candidate canonical native commitment frame, version 1 (task H.1; frozen by H.2).",
        "# Generated by `python3 scripts/check_zk_primitive_workloads.py --write-candidate-vectors`;",
        "# the BLAKE3 column comes from scripts/zk_blake3_reference.py and the Rust tests recompute it.",
        "# example <name> <algorithm> <catalog> <protocol> <profile> <role> <phase> <level> <index>",
        "#   <counter> <field count> <fields...> <frame> <blake3-256> <blake2b-256> <shake256/48>",
        "# Byte strings are hex; `-` is the empty string. Do not edit by hand.",
    ]
    for example in frame_spec["examples"]:
        frame = encode_candidate_frame(example, frame_spec)
        row = ["example", example["name"]]
        row += [
            example[name].encode("ascii").hex() or "-"
            for name in ("algorithm", "catalog", "protocol", "profile", "role", "phase")
        ]
        row += [str(example[name]) for name in ("level", "index", "counter")]
        row.append(str(len(example["fields_hex"])))
        row += [field or "-" for field in example["fields_hex"]]
        row += [
            frame.hex(),
            blake3_reference.blake3(frame).hex(),
            hashlib.blake2b(frame, digest_size=32).hexdigest(),
            hashlib.shake_256(frame).hexdigest(48),
        ]
        lines.append(" ".join(row))
    return "\n".join(lines) + "\n"


def rust_usize_constant(text: str, name: str) -> Optional[int]:
    """Value of `const NAME: usize = <integer>;` in Rust source, or None."""
    match = re.search(rf"\bconst\s+{re.escape(name)}\s*:\s*usize\s*=\s*([0-9_]+)\s*;", text)
    return int(match.group(1).replace("_", "")) if match else None


def label_grammar(root: Path) -> re.Pattern[str]:
    """The public label grammar of the measurement crate, read from its source.

    Raises `ValueError` when the source no longer has the expected shape.
    """
    text = read_text(root, LABEL_GRAMMAR_SOURCE)
    bound = rust_usize_constant(text, "MAX_LABEL_BYTES")
    body = re.search(
        r"fn label_byte\(byte: u8\) -> bool \{\s*byte\.is_ascii_alphanumeric\(\)\s*\|\|\s*"
        r"matches!\(byte,([^)]*)\)\s*\}",
        text,
    )
    if bound is None or body is None:
        raise ValueError(f"{LABEL_GRAMMAR_SOURCE}: the label grammar is not in its expected form")
    extra = re.findall(r"b'(.)'", body.group(1))
    if len(extra) != len(body.group(1).split("|")):
        raise ValueError(f"{LABEL_GRAMMAR_SOURCE}: an unreadable label byte")
    return re.compile("[A-Za-z0-9" + "".join(re.escape(char) for char in extra) + "]{1,%d}\\Z" % bound)


# ---------------------------------------------------------------------------
# Derived tables
# ---------------------------------------------------------------------------


def lock_packages(root: Path) -> list[dict[str, str]]:
    """Packages of Cargo.lock as name, version and checksum."""
    try:
        text = (root / "Cargo.lock").read_text(encoding="utf-8")
    except OSError:
        return []
    packages = []
    for block in text.split("[[package]]")[1:]:
        fields = dict(re.findall(r'^(name|version|checksum) = "([^"]*)"', block, re.M))
        if "name" in fields:
            packages.append(fields)
    return packages


def derive(root: Path, spec: dict[str, Any], files: Sequence[str]) -> dict[str, Any]:
    """Every table the tree determines, from one read of each file."""
    scanner = Scanner(spec)
    roles = spec["digest_roles"]
    needles = {
        role["key"]: pinned_needles(role["pinned_value"]) for role in roles if role.get("pinned_value")
    }
    surfaces = {role["key"]: Surface(role["surface"]) for role in roles if role.get("surface")}
    carriers: dict[str, dict[str, list[str]]] = {key: {} for key in needles}
    type_files: dict[str, list[str]] = {key: [] for key in surfaces}
    poseidon = spec["bn254_poseidon"]
    helper_needles = poseidon["consumer_needles"]
    owner = poseidon["owner_crate"]
    own_paths = frozenset([spec_path_of(spec)] + spec["scan"].get("exclude_files", []))
    file_table: dict[str, list[str]] = {}
    tree_table: dict[str, set[str]] = {}
    consumers: dict[str, list[str]] = {}
    call_sites: list[str] = []
    legacy: list[str] = []
    oversized: list[str] = []
    for path in files:
        target = root / path
        try:
            if target.stat().st_size > MAX_FILE_BYTES:
                oversized.append(path)
                continue
            data = target.read_bytes()
        except OSError:
            continue
        if path not in own_paths:
            for key, forms in needles.items():
                found = carrier_forms(data, forms)
                if found:
                    carriers[key][path] = found
            for key, surface in surfaces.items():
                if surface.reads(path) and surface.names(data):
                    type_files[key].append(path)
        if not path.endswith(scanner.extensions):
            continue
        if scanner.scans(path):
            scanner.record(path, data, file_table, tree_table)
        text = data.decode("utf-8", "replace")
        tooling = path.startswith("scripts/")
        vendored = path.startswith("vendor/")
        if not tooling and not path.startswith(owner):
            found = sorted(needle for needle in helper_needles if needle in text)
            if found:
                consumers[path] = found
        if not vendored and PQ_CALL_SITE.search(text):
            call_sites.append(path)
        if not vendored and not tooling and LEGACY_PQ_LABEL.search(text.lower()):
            legacy.append(path)
    pq_packages = sorted(
        (
            {key: package.get(key, "") for key in ("name", "version", "checksum")}
            for package in lock_packages(root)
            if PQ_PACKAGE.search(package["name"])
        ),
        key=lambda package: package["name"],
    )
    return {
        "scan": scanner.tables(file_table, tree_table),
        "oversized": sorted(oversized),
        "carriers": {key: dict(sorted(found.items())) for key, found in carriers.items()},
        "type_files": {key: sorted(found) for key, found in type_files.items()},
        "producers": ProducerLedger(spec["producer_ledger"]).derive(root, files),
        "bn254_consumers": dict(sorted(consumers.items())),
        "pq_call_sites": sorted(call_sites),
        "pq_legacy_label_files": sorted(legacy),
        "pq_lock_packages": pq_packages,
    }


def spec_path_of(spec: dict[str, Any]) -> str:
    """Repository path of the specification itself."""
    return spec.get("artifact", DEFAULT_SPEC)


def refreshed(spec: dict[str, Any], derived: dict[str, Any]) -> dict[str, Any]:
    """Copy of the specification with every derived table replaced.

    Role assignments of producers are kept; a producer that is new gets an
    empty role, which the check rejects until a maintainer assigns one.
    """
    if derived["producers"].get("binding_errors"):
        raise ValueError("; ".join(derived["producers"]["binding_errors"]))
    result = json.loads(json.dumps(spec))
    result["scan"]["files"] = derived["scan"]["files"]
    result["scan"]["tree_units"] = derived["scan"]["tree_units"]
    result["scan"]["oversized_files"] = derived["oversized"]
    for role in result["digest_roles"]:
        if role.get("pinned_value"):
            role["pinned_value"]["carriers"] = derived["carriers"][role["key"]]
        if role.get("surface"):
            role["surface"]["type_files"] = derived["type_files"][role["key"]]
    ledger = result["producer_ledger"]
    recorded = ledger.get("production", {})
    production = {}
    for path, functions in derived["producers"]["production"].items():
        production[path] = {}
        for name, facts in functions.items():
            kept = recorded.get(path, {}).get(name, {})
            production[path][name] = dict(facts, role=kept.get("role", ""))
            if kept.get("role_note"):
                production[path][name]["role_note"] = kept["role_note"]
    ledger["production"] = production
    ledger["test_only_counts"] = derived["producers"]["test_only_counts"]
    ledger["unreached_files"] = derived["producers"]["unreached_files"]
    result["bn254_poseidon"]["consumers"] = derived["bn254_consumers"]
    result["post_quantum"]["call_sites"] = derived["pq_call_sites"]
    result["post_quantum"]["legacy_labels"]["files"] = derived["pq_legacy_label_files"]
    result["post_quantum"]["lock_packages"] = derived["pq_lock_packages"]
    refresh_semantic_profiles(result)
    return result


RETAINED_DECISIONS = ("retained-family", "standard-internal", "not-a-commitment")


def refresh_semantic_profiles(spec: dict[str, Any]) -> None:
    """Recompute the derived tables of the H.2 section in place.

    A retained profile is rebuilt from its role record, and its identity with
    it. A role without a disposition gets the retained disposition only when
    its own record already says it is a retained family, a standard-internal
    hash or not a commitment, and it does not use the unqualified six-lane
    digest; any other new role still fails until a maintainer decides it. A
    role that left the file loses its disposition and its retained profile.
    Each workload's profile lists are recomputed. Frozen profiles, dispositions
    that were decided and the identities measurements name are never changed,
    so a changed identity leaves its measurements inapplicable.
    """
    section = spec.get("semantic_profiles")
    if not isinstance(section, dict):
        return
    roles = {role["key"]: role for role in spec["digest_roles"]}
    dispositions = section.setdefault("role_dispositions", {})
    for key in [key for key in dispositions if key not in roles]:
        del dispositions[key]
    for key, role in roles.items():
        if (
            key not in dispositions
            and role.get("canonical_native", {}).get("decision") in RETAINED_DECISIONS
            and role["primitive"] != "digest384"
            and role["family"] in PROFILE_KIND_OF_FAMILY
        ):
            dispositions[key] = {"disposition": "retained", "profiles": ["retained." + key]}
    retained = []
    for key, role in roles.items():
        if dispositions.get(key, {}).get("disposition") != "retained":
            continue
        profile = {
            "name": "retained." + key,
            "kind": PROFILE_KIND_OF_FAMILY.get(role["family"], ""),
            "status": "retained",
            "identity": None,
            "role": key,
            "parameters": retained_parameters(role),
        }
        try:
            profile["identity"] = profile_reference.identity_of(profile)
        except profile_reference.ProfileError:
            pass
        retained.append(profile)
    section["retained_profiles"] = retained
    for workload in spec["workloads"].get("definitions", []):
        names, pending = workload_profiles(spec, workload)
        workload["profiles"] = names
        if pending:
            workload["profiles_not_frozen"] = pending
        else:
            workload.pop("profiles_not_frozen", None)
        identity = workload_profile_set(spec, names)
        if identity is None:
            workload.pop("profile_set_identity", None)
        else:
            workload["profile_set_identity"] = identity


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


class Report:
    """Collected inconsistencies."""

    def __init__(self) -> None:
        self.errors: list[str] = []

    def error(self, message: str) -> None:
        self.errors.append(message)

    def require(self, condition: bool, message: str) -> None:
        if not condition:
            self.error(message)


def compile_status(text: str, symbol: str) -> Optional[str]:
    """`production` or `test-only` for the item that holds `symbol` in a Rust file.

    The answer is lexical: a test attribute on the item or on an enclosing
    block. It does not see a `mod` declaration in another file. Returns None
    when the symbol is absent.
    """
    offset = text.find(symbol)
    if offset < 0:
        return None
    for block in rust_index.blocks(text):
        if block.header_start <= offset < block.end and block.test_only():
            return "test-only"
    # A bodiless item (a constant or a type) carries its attribute directly above it.
    line_start = text.rfind("\n", 0, offset) + 1
    above = text[:line_start].rstrip().splitlines()
    while above and above[-1].lstrip().startswith(("///", "#[")):
        if rust_index.TEST_ATTRIBUTE.match(above[-1].strip()[2:-1]):
            return "test-only"
        above.pop()
    return "production"


def check_site(root: Path, report: Report, owner: str, site: dict[str, Any]) -> None:
    """A site names an existing file that holds its symbol and literals."""
    path = site.get("path", "")
    if not path or not (root / path).is_file():
        report.error(f"{owner}: path {path!r} does not exist")
        return
    text = read_text(root, path)
    for needle in [site.get("symbol", "")] + list(site.get("literals", [])):
        if not needle:
            report.error(f"{owner}: {path} has an empty symbol or literal")
        elif needle not in text:
            report.error(f"{owner}: {path} no longer contains {needle!r}")
    compiled = site.get("compiled")
    if compiled is not None and site.get("symbol") and site["symbol"] in text:
        if compiled not in ("production", "test-only"):
            report.error(f"{owner}: {path} has an unknown compile status {compiled!r}")
        elif compile_status(text, site["symbol"]) != compiled:
            report.error(
                f"{owner}: {path} {site['symbol']!r} is recorded as {compiled} but the source shows "
                f"{compile_status(text, site['symbol'])}"
            )


def check_primitives(root: Path, spec: dict[str, Any], derived: dict[str, Any], report: Report) -> None:
    seen = set()
    used = {name for found in derived["scan"]["files"].values() for name in found}
    used |= {name for found in derived["scan"]["tree_units"].values() for name in found}
    for primitive in spec["digest_primitives"]:
        name = primitive.get("id", "")
        report.require(name not in seen, f"primitive {name!r} is listed twice")
        seen.add(name)
        for key in ("algorithm", "kind", "token", "output_bytes", "in_use"):
            report.require(key in primitive, f"primitive {name}: `{key}` is missing")
        report.require(primitive.get("kind") in PRIMITIVE_KINDS, f"primitive {name}: unknown kind")
        report.require(
            primitive.get("in_use") == (name in used),
            f"primitive {name}: in_use is {primitive.get('in_use')} but the scan "
            f"{'finds' if name in used else 'does not find'} it",
        )
        for owner in primitive.get("owners", []):
            check_site(root, report, f"primitive {name}", owner)
            report.require(
                len(owner.get("symbol", "")) >= 8,
                f"primitive {name}: owner symbol {owner.get('symbol')!r} is too short to anchor a definition",
            )
        if primitive.get("in_use"):
            report.require(bool(primitive.get("owners")), f"primitive {name}: an owner site is required")
        for wrapper in primitive.get("token", {}).get("wrappers", []):
            report.require(bool(wrapper.get("owner")), f"primitive {name}: wrapper {wrapper.get('symbol')!r} has no owner site")
            if wrapper.get("owner"):
                check_site(root, report, f"primitive {name} wrapper", wrapper["owner"])


def check_scan(spec: dict[str, Any], derived: dict[str, Any], report: Report) -> None:
    recorded_files = spec["scan"]["files"]
    fresh_files = derived["scan"]["files"]
    for path in sorted(set(recorded_files) | set(fresh_files)):
        recorded, fresh = recorded_files.get(path), fresh_files.get(path)
        if recorded is None:
            report.error(f"scan: {path} uses {fresh} and is not listed")
        elif fresh is None:
            report.error(f"scan: {path} is listed with {recorded} but names no primitive now")
        elif recorded != fresh:
            report.error(f"scan: {path} is listed with {recorded} but uses {fresh}")
    recorded_units = spec["scan"]["tree_units"]
    fresh_units = derived["scan"]["tree_units"]
    for unit in sorted(set(recorded_units) | set(fresh_units)):
        recorded, fresh = recorded_units.get(unit), fresh_units.get(unit)
        if recorded != fresh:
            report.error(f"scan: tree unit {unit} is listed with {recorded} but uses {fresh}")
    report.require(
        spec["scan"].get("oversized_files", []) == derived["oversized"],
        f"scan: files above {MAX_FILE_BYTES} bytes are not read and must be listed: {derived['oversized']}",
    )


def check_consumers(spec: dict[str, Any], derived: dict[str, Any], report: Report) -> None:
    scanner = Scanner(spec)
    consumers = spec["consumers"]
    roles = {role["key"]: role for role in spec["digest_roles"]}
    found: dict[tuple[str, str], str] = {}
    for path, primitives in derived["scan"]["files"].items():
        consumer = scanner.consumer_of(path)
        if consumer is None:
            report.error(f"scan: {path} matches no consumer rule")
            continue
        for primitive in primitives:
            found.setdefault((consumer, primitive), path)
    declared = set()
    for key, consumer in consumers.items():
        report.require(bool(ROLE_KEY.match(key)), f"consumer {key!r}: key is not a stable key")
        report.require(bool(consumer.get("description")), f"consumer {key}: description is missing")
        for primitive, use in consumer.get("uses", {}).items():
            declared.add((key, primitive))
            owner = f"consumer {key} / {primitive}"
            report.require(use.get("class") in USE_CLASSES, f"{owner}: unknown class")
            report.require(bool(use.get("note")), f"{owner}: note is missing")
            for role_key in use.get("roles", []):
                report.require(role_key in roles, f"{owner}: role {role_key!r} does not exist")
            if use.get("class") == "role":
                # A use classified as a role names at least one role of that primitive;
                # further keys are cross-references.
                report.require(
                    any(
                        roles.get(role_key, {}).get("primitive") == primitive
                        for role_key in use.get("roles", [])
                    ),
                    f"{owner}: class `role` needs a role whose primitive is {primitive}",
                )
    for (consumer, primitive), path in sorted(found.items()):
        if consumer not in consumers:
            report.error(f"scan: consumer {consumer!r} (first file {path}) is not described")
        elif (consumer, primitive) not in declared:
            report.error(
                f"consumer {consumer}: use of {primitive} (first file {path}) is not classified"
            )
    for consumer, primitive in sorted(declared - set(found)):
        report.error(f"consumer {consumer}: classified use of {primitive} no longer occurs")
    for role in spec["digest_roles"]:
        pair = (role.get("consumer"), role.get("primitive"))
        if pair[0] in consumers:
            use = consumers[pair[0]].get("uses", {}).get(pair[1])
            report.require(
                use is not None and role.get("key") in use.get("roles", []),
                f"role {role.get('key')}: consumer {pair[0]} does not list it under its use of {pair[1]}",
            )


def check_roles(root: Path, spec: dict[str, Any], derived: dict[str, Any], report: Report) -> None:
    primitives = {primitive["id"]: primitive for primitive in spec["digest_primitives"]}
    seen = set()
    for role in spec["digest_roles"]:
        key = role.get("key", "")
        owner = f"role {key}"
        report.require(bool(ROLE_KEY.match(key)), f"{owner}: key is not a stable key")
        report.require(key not in seen, f"{owner}: listed twice")
        seen.add(key)
        for field in ("consumer", "role", "family", "primitive", "output_bytes", "domain_separation"):
            report.require(bool(role.get(field)), f"{owner}: `{field}` is missing")
        report.require(role.get("consumer") in spec["consumers"], f"{owner}: unknown consumer")
        family = role.get("family")
        report.require(family in ROLE_FAMILIES, f"{owner}: unknown family {family!r}")
        primitive = primitives.get(role.get("primitive"))
        if primitive is None:
            report.error(f"{owner}: unknown primitive {role.get('primitive')!r}")
        else:
            if role.get("output_bytes") not in primitive["output_bytes"]:
                report.error(
                    f"{owner}: output of {role.get('output_bytes')} bytes is not one of "
                    f"{primitive['output_bytes']} for {primitive['id']}"
                )
            if family in ROLE_FAMILIES and primitive.get("kind") not in ROLE_FAMILIES[family]:
                report.error(
                    f"{owner}: family {family} cannot be served by a primitive of kind {primitive.get('kind')}"
                )
        report.require(bool(role.get("sites")), f"{owner}: at least one site is required")
        for site in role.get("sites", []):
            check_site(root, report, owner, site)
        native = role.get("canonical_native", {})
        decision = native.get("decision")
        if decision not in NATIVE_DECISIONS:
            report.error(f"{owner}: canonical_native.decision is invalid")
        elif family in ROLE_FAMILIES and family not in NATIVE_DECISIONS[decision]:
            report.error(f"{owner}: decision {decision} does not apply to a role of family {family}")
        if decision == "already-blake3":
            report.require(
                role.get("primitive") == "blake3",
                f"{owner}: decision already-blake3 requires the blake3 primitive",
            )
        report.require(bool(native.get("note")), f"{owner}: canonical_native.note is missing")
        check_seed(root, report, owner, native)
        pinned = role.get("pinned_value")
        if pinned:
            fresh = derived["carriers"].get(key, {})
            if pinned.get("carriers") != fresh:
                missing = sorted(set(fresh) - set(pinned.get("carriers", {})))
                stale = sorted(set(pinned.get("carriers", {})) - set(fresh))
                changed = sorted(
                    path for path in set(fresh) & set(pinned.get("carriers", {}))
                    if fresh[path] != pinned["carriers"][path]
                )
                report.error(
                    f"{owner}: pinned-value carriers differ (unlisted {missing}, stale {stale}, "
                    f"changed forms {changed})"
                )
        if decision in ("changes", "changes-with-profile", "provisional"):
            report.require(bool(role.get("surface")), f"{owner}: a changing role needs its `surface`")
        if role.get("surface"):
            check_surface(root, report, owner, role, derived["type_files"].get(key, []))


def check_seed(root: Path, report: Report, owner: str, native: dict[str, Any]) -> None:
    """A role that moves to the candidate records whether it binds proof internals."""
    decision = native.get("decision")
    seed = native.get("transcript_seed_check")
    if decision not in MOVING_DECISIONS:
        return
    if not isinstance(seed, dict) or not isinstance(seed.get("binds_proof_internals"), bool):
        report.error(f"{owner}: a role that moves to the candidate needs `transcript_seed_check`")
        return
    report.require(bool(seed.get("finding")), f"{owner}: transcript_seed_check.finding is missing")
    report.require(bool(seed.get("sites")), f"{owner}: transcript_seed_check needs evidence sites")
    for site in seed.get("sites", []):
        check_site(root, report, f"{owner} transcript-seed evidence", site)
    binds = seed["binds_proof_internals"]
    if decision == "changes" and binds:
        report.error(
            f"{owner}: the value binds proof internals, so it changes only with the proof profile "
            "(`changes-with-profile`)"
        )
    if decision == "changes-with-profile" and not binds:
        report.error(f"{owner}: `changes-with-profile` needs a value that binds proof internals")
    if binds and decision in ("provisional", "already-blake3"):
        report.require(
            bool(seed.get("coordination")),
            f"{owner}: a value that binds proof internals names the profile it changes with",
        )


def check_surface(root: Path, report: Report, owner: str, role: dict[str, Any], fresh: list[str]) -> None:
    """Type owners, SDK owners and generated fixtures of a commitment role."""
    surface = role["surface"]
    listed = surface.get("type_files", [])
    if listed != fresh:
        report.error(
            f"{owner}: files that name the commitment type differ (unlisted "
            f"{sorted(set(fresh) - set(listed))}, stale {sorted(set(listed) - set(fresh))})"
        )
    carriers = set(role.get("pinned_value", {}).get("carriers", {}))
    known = set(fresh) | carriers
    owners = surface.get("sdk_owners", [])
    for site in owners:
        check_site(root, report, f"{owner} SDK owner", site)
        sdk = site.get("sdk")
        report.require(sdk in SDKS, f"{owner}: SDK owner names an unknown SDK {sdk!r}")
        report.require(
            site.get("path") in known,
            f"{owner}: SDK owner {site.get('path')} neither names the type nor carries the value",
        )
        if sdk in SDK_PATH_ROOTS:
            report.require(
                str(site.get("path", "")).startswith(SDK_PATH_ROOTS[sdk]),
                f"{owner}: SDK owner {site.get('path')} is outside the {sdk} tree",
            )
    owned = {site.get("sdk") for site in owners}
    absent = surface.get("sdks_without_owner", {})
    for sdk in SDKS:
        if sdk in owned:
            report.require(sdk not in absent, f"{owner}: SDK {sdk} has an owner and a reason for having none")
            continue
        report.require(bool(absent.get(sdk)), f"{owner}: SDK {sdk} has neither an owner nor a recorded reason")
        roots = SDK_PATH_ROOTS.get(sdk, ())
        strays = sorted(path for path in known if roots and path.startswith(roots))
        report.require(
            not strays, f"{owner}: SDK {sdk} is recorded without an owner but {strays} name or carry the value"
        )
    for fixture in surface.get("fixtures", []):
        check_site(root, report, f"{owner} fixture", {"path": fixture.get("path", ""), "symbol": fixture.get("contains", "")})
        report.require(
            fixture.get("path") in known,
            f"{owner}: fixture {fixture.get('path')} neither names the type nor carries the value",
        )
        generator = fixture.get("generator")
        report.require(bool(generator), f"{owner}: fixture {fixture.get('path')} names no generator")
        if generator:
            check_site(root, report, f"{owner} fixture generator", generator)


def check_producers(spec: dict[str, Any], derived: dict[str, Any], report: Report) -> None:
    """Every production digest call of a ledger scope is listed with a role."""
    ledger = spec["producer_ledger"]
    for error in derived["producers"].get("binding_errors", []):
        report.error(error)
    report.require(
        ledger.get("included_domain_bindings", []) == derived["producers"].get("domain_bindings", []),
        "producer ledger: included-domain bindings differ from the derived source observation",
    )
    roles = {role["key"]: role for role in spec["digest_roles"]}
    recorded = ledger.get("production", {})
    fresh = derived["producers"]["production"]
    for path in sorted(set(recorded) | set(fresh)):
        listed, found = recorded.get(path, {}), fresh.get(path, {})
        for name in sorted(set(listed) | set(found)):
            owner = f"producer {path} {name}"
            if name not in listed:
                report.error(f"{owner}: calls {found[name]['primitives']} and is not listed")
                continue
            if name not in found:
                report.error(f"{owner}: is listed but no longer calls a digest in production")
                continue
            entry = listed[name]
            for field in ("primitives", "domains", "returns"):
                if entry.get(field) != found[name][field]:
                    report.error(f"{owner}: recorded {field} {entry.get(field)!r} differ from {found[name][field]!r}")
            role = roles.get(entry.get("role"))
            if role is None:
                report.error(f"{owner}: role {entry.get('role')!r} does not exist")
            elif role["primitive"] not in entry.get("primitives", []) and not entry.get("role_note"):
                report.error(
                    f"{owner}: role {role['key']} is of primitive {role['primitive']}, which the "
                    "function does not call; record a `role_note` if it only reaches it"
                )
    for field, key in (("test_only_counts", "test_only_counts"), ("unreached_files", "unreached_files")):
        report.require(
            ledger.get(field) == derived["producers"][key],
            f"producer ledger: `{field}` differs from the tree",
        )
    assigned = {entry.get("role") for functions in recorded.values() for entry in functions.values()}
    for consumer in REQUIRED_CONSUMERS:
        report.require(
            any(roles[key]["consumer"] == consumer for key in assigned if key in roles),
            f"producer ledger: no production producer is assigned to a role of consumer {consumer}",
        )


def check_canonical(root: Path, spec: dict[str, Any], report: Report) -> None:
    candidate = spec["canonical_native_commitment"]
    roles = {role["key"]: role for role in spec["digest_roles"]}
    for field in ("candidate", "status", "decision_rule", "security_rationale", "cost_rationale"):
        report.require(bool(candidate.get(field)), f"canonical native commitment: `{field}` is missing")
    for list_name, decisions in (
        ("consumers_that_change", ("changes", "changes-with-profile")),
        ("provisional", ("provisional",)),
        ("already_blake3", ("already-blake3",)),
    ):
        listed = [entry["role"] for entry in candidate.get(list_name, [])]
        expected = sorted(
            key for key, role in roles.items() if role["canonical_native"]["decision"] in decisions
        )
        report.require(
            sorted(listed) == expected,
            f"canonical native commitment: {list_name} {sorted(listed)} differs from the roles "
            f"marked `{'` or `'.join(decisions)}` {expected}",
        )
        for entry in candidate.get(list_name, []):
            report.require(bool(entry.get("change")), f"{list_name} {entry.get('role')}: `change` is missing")
            seed = roles.get(entry.get("role"), {}).get("canonical_native", {}).get("transcript_seed_check", {})
            if seed.get("binds_proof_internals"):
                report.require(
                    bool(entry.get("coordination")),
                    f"{list_name} {entry.get('role')}: the role binds proof internals, so its entry names "
                    "what it changes with",
                )
    families = candidate.get("distinct_families_retained", [])
    report.require(bool(families), "canonical native commitment: retained families are missing")
    retained = set()
    for family in families:
        for key in family.get("roles", []):
            role = roles.get(key)
            retained.add(key)
            if role is None:
                report.error(f"retained family {family.get('id')}: role {key!r} does not exist")
            elif role["canonical_native"]["decision"] in MOVING_DECISIONS:
                report.error(f"retained family {family.get('id')}: role {key} is marked as changing")
        report.require(bool(family.get("reason")), f"retained family {family.get('id')}: reason is missing")
    for key, role in roles.items():
        if role["canonical_native"]["decision"] not in MOVING_DECISIONS:
            report.require(key in retained, f"canonical native commitment: role {key} is in no retained family")
    readings = candidate.get("consumer_readings", {})
    for consumer in REQUIRED_CONSUMERS:
        moving = [
            key for key, role in roles.items()
            if role["consumer"] == consumer and role["canonical_native"]["decision"] in MOVING_DECISIONS
        ]
        report.require(bool(moving), f"canonical native commitment: no role of consumer {consumer} moves to the candidate")
        reading = readings.get(consumer, {})
        report.require(bool(reading.get("reading")), f"canonical native commitment: consumer {consumer} has no recorded reading")
        report.require(
            sorted(reading.get("roles", [])) == sorted(moving),
            f"canonical native commitment: reading of {consumer} lists {sorted(reading.get('roles', []))}, "
            f"its moving roles are {sorted(moving)}",
        )
    check_frame(root, candidate.get("frame", {}), report)
    for measurement in candidate.get("exploratory_measurements", []):
        check_exploratory(measurement, "canonical native commitment", report)


def check_frame(root: Path, frame: dict[str, Any], report: Report) -> None:
    """The frame the specification states is the pinned one and matches the vectors."""
    layout = tuple(
        (entry.get("field"), entry.get("tag"), entry.get("kind"))
        for entry in sorted(frame.get("layout", []), key=lambda item: item.get("order", 0))
    )
    if layout != FRAME_LAYOUT_V1:
        report.error("candidate frame: the layout differs from frame version 1")
        return
    orders = [entry.get("order") for entry in frame.get("layout", [])]
    report.require(sorted(orders) == list(range(1, len(orders) + 1)), "candidate frame: layout order is not a sequence")
    report.require(frame.get("version") == 1, "candidate frame: version differs")
    report.require(len(frame.get("semantics", [])) >= 5, "candidate frame: semantics are missing")
    names = [example.get("name") for example in frame.get("examples", [])]
    report.require(len(names) == len(set(names)) and len(names) >= 8, "candidate frame: examples are missing or repeated")
    fixture = frame.get("vectors", "")
    reference = frame.get("reference_encoder_test", "")
    try:
        existing = read_text(root, fixture)
        rust = read_text(root, reference)
    except OSError as error:
        report.error(f"candidate frame: {error}")
        return
    bounds = frame.get("bounds", {})
    for field, constant in FRAME_BOUND_CONSTANTS.items():
        report.require(
            bounds.get(field) == rust_usize_constant(rust, constant),
            f"candidate frame: bound {field} differs from {constant} in {reference}",
        )
    report.require(
        bounds.get("payload_field_max_bytes") == 2**32 - 1 and "u32::try_from(field.len())" in rust,
        f"candidate frame: the payload field bound differs from the u32 check in {reference}",
    )
    magic = f'b"{frame.get("magic_ascii", "")}\\0"'
    report.require(magic in rust, f"candidate frame: magic differs from {reference}")
    try:
        rendered = render_candidate_vectors({"canonical_native_commitment": {"frame": frame}})
        frames = {
            example["name"]: encode_candidate_frame(example, frame) for example in frame.get("examples", [])
        }
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        report.error(f"candidate frame: an example cannot be encoded: {error}")
        return
    if existing != rendered:
        report.error(f"candidate frame: {fixture} differs from the frame the specification describes")
    for left, right in FRAME_DISTINCT_EXAMPLES:
        if left not in frames or right not in frames:
            report.error(f"candidate frame: examples {left} and {right} are required")
        elif frames[left] == frames[right]:
            report.error(f"candidate frame: examples {left} and {right} encode to the same frame")
    for error in blake3_reference.self_check():
        report.error(f"candidate frame: {error}")


def check_exploratory(measurement: dict[str, Any], owner: str, report: Report) -> None:
    """A recorded measurement is labelled exploratory and never a qualification."""
    report.require(measurement.get("label") == "exploratory", f"{owner}: a measurement is not labelled exploratory")
    report.require(measurement.get("qualification") is False, f"{owner}: a measurement claims qualification")
    for field in ("source_commit", "hardware", "command", "conditions", "results"):
        report.require(bool(measurement.get(field)), f"{owner}: measurement `{field}` is missing")


def check_poseidon(root: Path, spec: dict[str, Any], derived: dict[str, Any], report: Report) -> None:
    section = spec["bn254_poseidon"]
    try:
        fresh = poseidon_reference.build_report(root)
        fixture = poseidon_reference.render_vector_fixture(fresh["vectors"])
    except (OSError, ValueError) as error:
        report.error(f"BN254 Poseidon: {error}")
        return
    if read_text(root, poseidon_reference.VECTOR_FIXTURE) != fixture:
        report.error(f"BN254 Poseidon: {poseidon_reference.VECTOR_FIXTURE} differs from the regenerated vectors")
    fresh.pop("vectors")
    report.require(
        section.get("regeneration") == fresh,
        "BN254 Poseidon: recorded regeneration facts differ from the recomputed ones",
    )
    report.require(
        section.get("consumers") == derived["bn254_consumers"],
        "BN254 Poseidon: helper consumers differ from the scan "
        f"(unlisted {sorted(set(derived['bn254_consumers']) - set(section.get('consumers', {})))}, "
        f"stale {sorted(set(section.get('consumers', {})) - set(derived['bn254_consumers']))})",
    )
    for site in section.get("sites", []):
        check_site(root, report, "BN254 Poseidon", site)
    defects = {defect["id"]: defect for defect in section.get("defects", [])}
    widths = fresh["widths"]
    for identifier in REQUIRED_BN254_DEFECTS:
        report.require(identifier in defects, f"BN254 Poseidon: defect {identifier} is missing")
        report.require(defects.get(identifier, {}).get("disposition") == "corrected-source-qualification-pending", f"BN254 Poseidon: defect {identifier} lacks the explicit current qualification limit")
    report.require(widths["3"]["repository_partial_rounds"] == 57 and widths["6"]["repository_partial_rounds"] == 60, "BN254 Poseidon: current round counts differ from H.2")
    report.require(fresh["published_width3"]["mds_equal_to_repository"] and fresh["published_width3"]["round_constants_shared_with_repository"] == 195, "BN254 Poseidon: the selected width-three bank differs from the published permutation")
    # D3 is a property of the helper modes, anchored on their source.
    mode = defects.get("BN254-POSEIDON-D3", {})
    report.require(bool(mode), "BN254 Poseidon: defect BN254-POSEIDON-D3 is missing")
    report.require(bool(mode.get("sites")), "BN254-POSEIDON-D3: the helper sites that show the mode are missing")
    for site in mode.get("sites", []):
        check_site(root, report, "BN254-POSEIDON-D3", site)
    for identifier, defect in defects.items():
        for field in ("title", "class", "evidence", "consumer_needles", "owner_task"):
            report.require(bool(defect.get(field)), f"{identifier}: `{field}` is missing")
        report.require(
            set(defect.get("consumer_needles", [])) <= set(section["consumer_needles"]),
            f"{identifier}: a consumer needle is not scanned",
        )
        report.require(defect.get("owner_task") == "F.5", f"{identifier}: parameter changes belong to F.5")


def sdk_manifest_pq_library(path: str, text: str) -> str | None:
    """Find a PQ library name without mistaking Swift evidence keys for dependencies.

    The native artifact validator compares an evidence-key set with literal
    filenames. Only its exact normalization receipt filename is metadata;
    occurrences in dependencies, linker settings or other expressions still fail.
    """
    metadata_spans = []
    if path.endswith("/Package.swift"):
        for guard in re.finditer(
            r'\bSet\(\s*evidence\.keys\s*\)\s*==\s*Set\(\s*\['
            r'(?P<names>\s*(?:"[^"\\\n]*"\s*,?\s*)*)\]\s*\)',
            text,
        ):
            for name in re.finditer(r'"pqcrypto-normalization\.json"', guard["names"]):
                metadata_spans.append(
                    (guard.start("names") + name.start(), guard.start("names") + name.end())
                )
    for match in SDK_PQ_LIBRARY.finditer(text):
        if not any(start <= match.start() and match.end() <= end for start, end in metadata_spans):
            return match.group(0)
    return None


def check_post_quantum(root: Path, spec: dict[str, Any], derived: dict[str, Any], files: Sequence[str], report: Report) -> None:
    section = spec["post_quantum"]
    report.require(
        section.get("lock_packages") == derived["pq_lock_packages"],
        f"post-quantum: Cargo.lock packages {derived['pq_lock_packages']} differ from the recorded ones",
    )
    for package in lock_packages(root):
        if SUPERSEDED_PQ_PACKAGES.search(package["name"]):
            report.error(f"post-quantum: Cargo.lock holds superseded package {package['name']}")
    report.require(
        section.get("call_sites") == derived["pq_call_sites"],
        "post-quantum: call sites differ from the scan "
        f"(unlisted {sorted(set(derived['pq_call_sites']) - set(section.get('call_sites', [])))}, "
        f"stale {sorted(set(section.get('call_sites', [])) - set(derived['pq_call_sites']))})",
    )
    legacy = section.get("legacy_labels", {})
    report.require(
        legacy.get("files") == derived["pq_legacy_label_files"],
        "post-quantum: files with a superseded algorithm label differ from the scan "
        f"(unlisted {sorted(set(derived['pq_legacy_label_files']) - set(legacy.get('files', [])))}, "
        f"stale {sorted(set(legacy.get('files', [])) - set(derived['pq_legacy_label_files']))})",
    )
    for site in legacy.get("wire_visible", []):
        check_site(root, report, "post-quantum legacy label", site)
        report.require(bool(site.get("replacement_changes")), f"legacy label {site.get('symbol')}: wire change is missing")
    for error in pq_reference.check_fixtures(root):
        report.error(f"post-quantum: {error}")
    recorded = {entry["id"]: entry for entry in section.get("parameter_sets", [])}
    for suite, digest in pq_reference.OFFICIAL_NISTKAT_SHA256.items():
        entry = recorded.get(suite)
        if entry is None:
            report.error(f"post-quantum: parameter set {suite} is not recorded")
            continue
        report.require(entry.get("official_nistkat_sha256") == digest, f"post-quantum: {suite} digest differs")
        report.require(entry.get("response") == pq_reference.response_path(suite), f"post-quantum: {suite} response path differs")
        report.require(
            tuple(entry.get("encoded_bytes", {}).values()) == pq_reference.FIPS_LENGTHS[suite],
            f"post-quantum: {suite} encoded lengths differ from the FIPS lengths",
        )
        pinned = entry.get("rust_pin", {})
        check_site(root, report, f"post-quantum {suite} Rust pin", {"path": pinned.get("path", ""), "symbol": digest})
    for test in section.get("tests", []):
        check_site(root, report, "post-quantum test", {"path": test["path"], "symbol": f"fn {test['name']}("})
    for path in files:
        if path.startswith(SDK_ROOTS) and SDK_MANIFEST.search(path):
            match = sdk_manifest_pq_library(path, read_text(root, path))
            if match and path not in section.get("sdk_manifests_with_pq_library", []):
                report.error(f"post-quantum: SDK manifest {path} names {match!r}")
    for site in section.get("jvm_bouncycastle", {}).get("manifests", []):
        check_site(root, report, "post-quantum BouncyCastle manifest", site)
    for path in files:
        if path.startswith(SDK_ROOTS) and path.endswith(JVM_SOURCE):
            match = BOUNCYCASTLE_PQ.search(read_text(root, path))
            if match:
                report.error(
                    f"post-quantum: {path} uses the BouncyCastle post-quantum class {match.group(0)!r}"
                )
    findings = {finding.get("id"): finding for finding in section.get("findings", [])}
    for identifier in REQUIRED_PQ_FINDINGS:
        report.require(identifier in findings, f"post-quantum: finding {identifier} is missing")
    for finding in section.get("findings", []):
        for field in ("id", "title", "class", "evidence", "owner_task"):
            report.require(bool(finding.get(field)), f"post-quantum finding {finding.get('id')}: `{field}` is missing")
        for site in finding.get("sites", []):
            check_site(root, report, f"post-quantum finding {finding.get('id')}", site)
    for site in section.get("in_tree_implementations", []):
        check_site(root, report, "post-quantum in-tree implementation", site)
        report.require(bool(site.get("finding")), f"in-tree implementation {site.get('path')}: finding id is missing")
        report.require(site.get("finding") in findings, f"in-tree implementation {site.get('path')}: unknown finding")


def check_workloads(root: Path, spec: dict[str, Any], report: Report) -> None:
    section = spec["workloads"]
    inventory_path = section.get("backend_inventory", "")
    try:
        inventory = json.loads(read_text(root, inventory_path))
        known = {entry["id"] for entry in inventory["consumers"]}
        known |= {entry["id"] for entry in inventory["distinct_families"]}
        known |= {entry["id"] for entry in inventory["roles_without_an_engine"]}
    except (OSError, ValueError, KeyError) as error:
        report.error(f"workloads: backend inventory {inventory_path!r}: {error}")
        known = set()
    try:
        label = label_grammar(root)
    except (OSError, ValueError) as error:
        report.error(f"workloads: {error}")
        return
    report.require(section.get("label") == "exploratory", "workloads: the section is not labelled exploratory")
    report.require(bool(section.get("final_measurement_task") == "H.3"), "workloads: final measurement belongs to H.3")
    wg = section.get("state_candidates", {})
    report.require(wg.get("owner_task") == "G.2", "workloads: State candidate measurement belongs to G.2")
    kinds = section.get("kinds", {})
    report.require(bool(kinds) and "state" not in kinds, "workloads: the workload kinds are missing or include State")
    primitives = {primitive["id"] for primitive in spec["digest_primitives"]}
    roles = {role["key"] for role in spec["digest_roles"]}
    seen = set()
    covered = set()
    for workload in section.get("definitions", []):
        identifier = workload.get("id", "")
        owner = f"workload {identifier}"
        report.require(bool(label.match(identifier)), f"{owner}: id is outside the measurement label grammar")
        report.require(identifier not in seen, f"{owner}: listed twice")
        seen.add(identifier)
        report.require(workload.get("label") == "exploratory", f"{owner}: not labelled exploratory")
        report.require(
            workload.get("kind") in kinds,
            f"{owner}: kind {workload.get('kind')!r} is not a workload kind of this file; State candidates belong to G.2",
        )
        for field in ("kind", "question", "shapes", "measured", "phases", "flow"):
            report.require(bool(workload.get(field)), f"{owner}: `{field}` is missing")
        report.require(
            not STATE_WORKLOAD.search(f"{identifier} {workload.get('question', '')}"),
            f"{owner}: State tree and hash candidates are measured by G.2, not defined here",
        )
        for phase in workload.get("phases", []):
            report.require(bool(label.match(phase)), f"{owner}: phase {phase!r} is outside the label grammar")
        for consumer in workload.get("backend_consumers", []):
            covered.add(consumer)
            report.require(consumer in known, f"{owner}: backend consumer {consumer!r} is not in {inventory_path}")
        for primitive in workload.get("primitives", []):
            report.require(primitive in primitives, f"{owner}: unknown primitive {primitive!r}")
        for role in workload.get("roles", []):
            report.require(role in roles, f"{owner}: unknown role {role!r}")
        for measurement in workload.get("exploratory_measurements", []):
            check_exploratory(measurement, owner, report)
    report.require(
        known <= covered,
        f"workloads: no workload for backend consumers {sorted(known - covered)}",
    )
    harness = section.get("harness", {})
    check_site(root, report, "workloads harness", harness)


def check_transcript(root: Path, spec: dict[str, Any], report: Report) -> None:
    section = spec["shared_transcript_requirements"]
    report.require(section.get("consumed_by") == "H.2", "transcript requirements: the consumer is H.2")
    order = [entry.get("order") for entry in section.get("binding_order", [])]
    report.require(order == list(range(1, len(order) + 1)) and len(order) >= 7, "transcript requirements: binding order is not a complete sequence")
    for entry in section.get("binding_order", []):
        report.require(bool(entry.get("binds")) and bool(entry.get("before")), f"transcript requirement {entry.get('order')}: `binds` or `before` is missing")
    for field in ("framing", "grinding", "security_claims", "candidate"):
        report.require(bool(section.get(field)), f"transcript requirements: `{field}` is missing")
    claims = section.get("security_claims", {})
    for model in ("classical_rom", "qrom"):
        report.require(bool(claims.get(model)), f"transcript requirements: the {model} claim is missing")
    listed: dict[str, dict[str, Any]] = {}
    for site in section.get("current_implementations", []):
        check_site(root, report, "transcript implementation", site)
        report.require(bool(site.get("engine")), f"transcript implementation {site.get('path')}: engine is missing")
        report.require(site.get("engine") not in listed, f"transcript implementation {site.get('engine')}: listed twice")
        listed[site.get("engine")] = site
    inventory_path = section.get("engine_inventory", "")
    try:
        engines = {
            entry["id"]: bool(entry.get("components", {}).get("transcript"))
            for entry in json.loads(read_text(root, inventory_path))["engines"]
        }
    except (OSError, ValueError, KeyError) as error:
        report.error(f"transcript requirements: engine inventory {inventory_path!r}: {error}")
        return
    report.require(
        set(listed) == set(engines),
        f"transcript requirements: engines {sorted(listed)} differ from those of {inventory_path} {sorted(engines)}",
    )
    for engine, own in engines.items():
        site = listed.get(engine)
        if site is not None:
            report.require(
                site.get("own_transcript") is own,
                f"transcript implementation {engine}: own_transcript is {site.get('own_transcript')} but "
                f"{inventory_path} {'records' if own else 'does not record'} a transcript component",
            )


PROFILE_STATUSES = ("frozen", "retained")
ROLE_DISPOSITIONS = ("frozen-profile", "retained", "blocked", "deferred", "retired-at-migration")
NOT_FROZEN_STATUSES = ("blocked", "deferred", "retired-at-migration")
DEFECT_DISPOSITIONS = (
    "corrected",
    "evidence-pending",
    "frozen-as-implemented-and-relabelled",
    "replaced-or-deferred",
)
REQUIRED_DEFECT_DISPOSITIONS = (
    "BN254-POSEIDON-D1", "BN254-POSEIDON-D2", "BN254-POSEIDON-D3",
    "PQ-D1", "PQ-D2", "PQ-D3", "SIX-LANE-NATIVE-ROLES",
)  # fmt: skip
PROFILE_KIND_OF_FAMILY = {
    "native": "native-commitment",
    "in-circuit": "in-circuit-digest",
    "proof-internal": "transcript",
    "kdf": "key-derivation",
    "standard-internal": "standard-primitive",
}
# A profile is semantic data: none of these words is a parameter key token.
EVIDENCE_METADATA_TOKENS = frozenset(
    ("source", "build", "binary", "toolchain", "commit", "revision", "git", "measurement", "measured", "review", "qualification")
)
UNQUALIFIED_DIGEST = re.compile(r"digest384|six-lane", re.I)
TEST_PATH = re.compile(r"backend::(?P<module>[a-z0-9_]+(?:::[a-z0-9_]+)*)::(?P<test>[a-z0-9_]+)\Z")
TRANSCRIPT_ENGINE_DISPOSITIONS = ("frozen", "adopts-at-migration", "retired-at-migration", "conditional")


def retained_parameters(role: dict[str, Any]) -> list[dict[str, Any]]:
    """Derive a retained frame from its explicit role-owned semantic values.

    Primitive-wide descriptive prose is not a semantic parameter owner. A
    missing role algorithm is an error, including during regeneration; there
    is no fallback to the primitive summary or to an earlier profile frame.
    """
    algorithm = role.get("algorithm")
    if not isinstance(algorithm, str) or not algorithm.strip():
        raise profile_reference.ProfileError("retained role algorithm is missing or empty")

    def parameter(key: str, kind: str, value: Any) -> dict[str, Any]:
        return {"key": key, "type": kind, "value": value}

    return [
        parameter("profile_version", "u64", 1),
        parameter("role", "text", role["key"]),
        parameter("primitive", "text", role["primitive"]),
        parameter("algorithm", "text", algorithm),
        parameter("output_bytes", "u64", role["output_bytes"]),
        parameter("domain_separation", "text", role["domain_separation"]),
    ]


def workload_profiles(spec: dict[str, Any], workload: dict[str, Any]) -> tuple[list[str], list[str]]:
    """The frozen profiles and the pending selections one workload depends on."""
    section = spec["semantic_profiles"]
    dispositions = section["role_dispositions"]
    names: list[str] = []
    pending: list[str] = []
    for role in workload.get("roles", []):
        entry = dispositions.get(role, {})
        for name in entry.get("profiles", []):
            if name not in names:
                names.append(name)
        if "not_frozen" in entry and entry["not_frozen"] not in pending:
            pending.append(entry["not_frozen"])
    transcript = section["shared_transcript"]["profile"]
    if workload.get("kind") == "shared-backend" and transcript not in names:
        names.insert(0, transcript)
    return names, pending


def workload_profile_set(spec: dict[str, Any], names: Sequence[str]) -> Optional[str]:
    """The one identity of a workload's ordered profiles, or `None` when it names none or an unknown one."""
    section = spec["semantic_profiles"]
    identities = {profile.get("name"): profile.get("identity") for profile in section.get("profiles", []) + section.get("retained_profiles", [])}
    try:
        return profile_reference.profile_set_identity([identities[name] for name in names]) if names else None
    except (KeyError, TypeError, ValueError):
        return None


def recorded_measurements(spec: dict[str, Any]) -> Iterator[tuple[str, str, list[str], dict[str, Any]]]:
    """Each measurement's scope and complete profile set, derived from its owning section.

    The native candidate comparison measures bare primitives, not frozen frame
    profiles. Runs recorded inside workloads measure those workloads' profiles.
    A measurement cannot choose a weaker scope by changing its own metadata.
    """
    for measurement in spec["canonical_native_commitment"].get("exploratory_measurements", []):
        yield f"measurement {measurement.get('id')}", "bare-primitives", [], measurement
    for workload in spec["workloads"].get("definitions", []):
        for measurement in workload.get("exploratory_measurements", []):
            yield f"measurement {measurement.get('id')}", "workload-profiles", workload.get("profiles", []), measurement


def check_semantic_profiles(root: Path, spec: dict[str, Any], report: Report) -> None:
    """The H.2 selections: identities, dispositions, the frozen transcript and measurement binding."""
    section = spec["semantic_profiles"]
    report.require(section.get("task") == "H.2", "semantic profiles: the section belongs to H.2")
    identity = section.get("identity", {})
    frame = identity.get("frame", {})
    report.require(
        (frame.get("magic_ascii", "") + "\0").encode() == profile_reference.MAGIC,
        "semantic profiles: the recorded frame magic differs from the reference",
    )
    report.require(frame.get("kinds") == list(profile_reference.KINDS), "semantic profiles: the kinds differ from the reference")
    report.require(
        frame.get("bounds")
        == {
            "parameters": profile_reference.MAX_PARAMETERS,
            "label_bytes": profile_reference.MAX_LABEL_BYTES,
            "value_bytes": profile_reference.MAX_VALUE_BYTES,
        },
        "semantic profiles: the frame bounds differ from the reference",
    )
    owner_text = ""
    try:
        owner_text = read_text(root, identity.get("rust_owner", {}).get("path", ""))
    except OSError as error:
        report.error(f"semantic profiles: Rust identity owner: {error}")
    for name, value in (
        ("SEMANTIC_PROFILE_MAX_PARAMETERS_V1", profile_reference.MAX_PARAMETERS),
        ("SEMANTIC_PROFILE_MAX_LABEL_BYTES_V1", profile_reference.MAX_LABEL_BYTES),
    ):
        report.require(rust_usize_constant(owner_text, name) == value, f"semantic profiles: Rust constant {name} differs from the reference")
    report.require(
        'b"' + profile_reference.MAGIC[:-1].decode() + '\\0"' in owner_text,
        "semantic profiles: the Rust owner does not carry the frame magic",
    )
    for kind in profile_reference.KINDS:
        report.require(f'"{kind}"' in owner_text, f"semantic profiles: the Rust owner has no kind {kind!r}")
    for site in (identity.get("rust_owner", {}),):
        check_site(root, report, "semantic profile identity owner", site)
    excluded = " ".join(identity.get("excluded_inputs", []))
    for word in ("source", "build", "measurement", "caller"):
        report.require(word in excluded, f"semantic profiles: excluded inputs do not name {word!r}")

    primitives = {primitive["id"]: primitive for primitive in spec["digest_primitives"]}
    roles = {role["key"]: role for role in spec["digest_roles"]}
    profiles: dict[str, dict[str, Any]] = {}
    for group, status in (("profiles", "frozen"), ("retained_profiles", "retained")):
        for profile in section.get(group, []):
            name = profile.get("name", "")
            owner = f"profile {name}"
            report.require(name not in profiles, f"{owner}: listed twice")
            profiles[name] = profile
            report.require(profile.get("status") == status, f"{owner}: status is not {status!r}")
            try:
                computed = profile_reference.identity_of(profile)
            except (profile_reference.ProfileError, KeyError, TypeError) as error:
                report.error(f"{owner}: not a canonical profile: {error}")
                continue
            report.require(
                profile.get("identity") == computed,
                f"{owner}: recorded identity {profile.get('identity')} differs from the identity {computed} of its parameters",
            )
            for parameter in profile.get("parameters", []):
                tokens = set(re.split(r"[._-]", parameter.get("key", "")))
                report.require(
                    not tokens & EVIDENCE_METADATA_TOKENS,
                    f"{owner}: parameter {parameter.get('key')!r} names evidence metadata; an identity holds semantic data only",
                )
            if status == "frozen":
                text = json.dumps(profile.get("parameters", []))
                report.require(
                    not UNQUALIFIED_DIGEST.search(text) and not UNQUALIFIED_DIGEST.search(name),
                    f"{owner}: a frozen profile names the unqualified six-lane digest",
                )
                report.require(
                    "state" not in re.split(r"[._-]", name),
                    f"{owner}: the State tree and hash are selected by G.3, not frozen here",
                )
                report.require(bool(profile.get("summary")) and bool(profile.get("implemented_by")), f"{owner}: summary or implementing task is missing")
                site = profile.get("typed_owner")
                if site is not None:
                    check_site(root, report, owner, site)
                else:
                    report.require(bool(profile.get("typed_owner_pending")), f"{owner}: neither a typed owner nor its pending statement")
                for anchor in profile.get("evidence_metadata", {}).get("anchors", []):
                    try:
                        report.require(anchor["contains"] in read_text(root, anchor["path"]), f"{owner}: anchor {anchor['contains']!r} is missing from {anchor['path']}")
                    except OSError as error:
                        report.error(f"{owner}: {error}")
            else:
                role = roles.get(profile.get("role"))
                if role is None:
                    report.error(f"{owner}: retained profile of an unknown role")
                    continue
                report.require(name == "retained." + role["key"], f"{owner}: name does not derive from its role")
                report.require(profile.get("kind") == PROFILE_KIND_OF_FAMILY.get(role["family"]), f"{owner}: kind does not follow the role family")
                try:
                    expected_parameters = retained_parameters(role)
                except profile_reference.ProfileError as error:
                    report.error(f"{owner}: {error}")
                else:
                    report.require(
                        profile.get("parameters") == expected_parameters,
                        f"{owner}: parameters differ from the role record; a changed role is a new identity",
                    )

    not_frozen = {entry.get("id"): entry for entry in section.get("not_frozen", [])}
    for identifier, entry in not_frozen.items():
        owner = f"not frozen {identifier}"
        report.require(entry.get("status") in NOT_FROZEN_STATUSES, f"{owner}: unknown status")
        for field in ("reason", "missing", "decided_by", "roles"):
            report.require(bool(entry.get(field)), f"{owner}: `{field}` is missing")
        report.require(identifier not in profiles, f"{owner}: also listed as a profile")

    dispositions = section.get("role_dispositions", {})
    report.require(set(dispositions) == set(roles), f"semantic profiles: role dispositions differ from the digest roles: {sorted(set(dispositions) ^ set(roles))}")
    for key, entry in dispositions.items():
        role = roles.get(key)
        if role is None:
            continue
        owner = f"role disposition {key}"
        disposition = entry.get("disposition")
        report.require(disposition in ROLE_DISPOSITIONS, f"{owner}: unknown disposition {disposition!r}")
        if disposition in ("frozen-profile", "retained"):
            names = entry.get("profiles", [])
            report.require(bool(names), f"{owner}: names no profile")
            for name in names:
                profile = profiles.get(name)
                report.require(profile is not None, f"{owner}: unknown profile {name!r}")
                if profile is not None:
                    expected = "frozen" if disposition == "frozen-profile" else "retained"
                    report.require(profile.get("status") == expected, f"{owner}: profile {name} is not {expected}")
        else:
            target = not_frozen.get(entry.get("not_frozen"))
            report.require(target is not None and key in target.get("roles", []), f"{owner}: its not-frozen entry does not list it")
            if target is not None:
                report.require(target.get("status") == disposition, f"{owner}: disposition differs from its not-frozen entry")
        if role["primitive"] == "digest384":
            report.require(
                disposition != "retained" and (disposition != "frozen-profile" or bool(entry.get("replaces"))),
                f"{owner}: the unqualified six-lane digest is retained or frozen instead of replaced, deferred or blocked",
            )
        decision = role.get("canonical_native", {}).get("decision")
        if decision == "changes-with-profile":
            report.require(disposition == "frozen-profile", f"{owner}: a changing role has no frozen profile")
            for field in ("required_property", "accepted_level"):
                report.require(bool(entry.get(field)), f"{owner}: `{field}` of the selected native commitment is missing")
        if decision == "provisional":
            report.require(disposition == "deferred", f"{owner}: a provisional role must stay deferred")
        if role["family"] == "native" and disposition == "frozen-profile" and role["primitive"] != "poseidon":
            for field in ("required_property", "accepted_level"):
                report.require(bool(entry.get(field)), f"{owner}: `{field}` is missing")

    recorded = {entry.get("defect"): entry for entry in section.get("defect_dispositions", [])}
    known_defects = {defect["id"] for defect in spec["bn254_poseidon"]["defects"]} | {finding["id"] for finding in spec["post_quantum"]["findings"]}
    for identifier in REQUIRED_DEFECT_DISPOSITIONS:
        report.require(identifier in recorded, f"semantic profiles: no disposition for defect {identifier}")
    for identifier in known_defects:
        report.require(identifier in recorded, f"semantic profiles: defect {identifier} of this file has no disposition")
    for identifier, entry in recorded.items():
        owner = f"defect disposition {identifier}"
        report.require(entry.get("disposition") in DEFECT_DISPOSITIONS, f"{owner}: unknown disposition {entry.get('disposition')!r}")
        for field in ("correction", "implemented_by", "vectors_required"):
            report.require(bool(entry.get(field)), f"{owner}: `{field}` is missing")
        named = list(entry.get("profiles", [])) + ([entry["profile"]] if entry.get("profile") else [])
        for name in named:
            report.require(profiles.get(name, {}).get("status") == "frozen", f"{owner}: {name!r} is not a frozen profile")
        for role in entry.get("roles", {}):
            report.require(role in roles, f"{owner}: unknown role {role!r}")

    check_frozen_parameters(root, spec, profiles, report)
    check_frozen_transcript(root, spec, profiles, report)
    check_measurement_binding(spec, profiles, report)


_GENERATED_TABLES: dict[tuple[int, int], tuple[list[list[int]], list[list[int]]]] = {}


def generated_tables(width: int, partial: int) -> tuple[list[list[int]], list[list[int]]]:
    """Regenerated BN254 Poseidon tables for one width and partial-round count, computed once."""
    key = (width, partial)
    if key not in _GENERATED_TABLES:
        _GENERATED_TABLES[key] = poseidon_reference.generate_parameters(width, poseidon_reference.FULL_ROUNDS, partial)
    return _GENERATED_TABLES[key]


def check_frozen_parameters(root: Path, spec: dict[str, Any], profiles: dict[str, dict[str, Any]], report: Report) -> None:
    """Frozen parameters agree with the records and generators they are taken from."""
    del root
    frame = spec["canonical_native_commitment"]["frame"]
    native = profiles.get("native.commitment.blake3-256.frame-v1")
    if native is None:
        report.error("semantic profiles: the canonical native commitment profile is missing")
    else:
        values = profile_reference.parameter_map(native)
        report.require(values.get("frame_version") == frame["version"], "native commitment profile: frame version differs from the frame")
        report.require(values.get("frame_magic") == (frame["magic_ascii"].encode() + b"\0").hex(), "native commitment profile: frame magic differs from the frame")
        layout = ";".join(
            f"{entry['order']}:{entry['field']}:{entry['kind']}" + (f":tag={entry['tag']}" if "tag" in entry else "")
            for entry in frame["layout"]
        )
        report.require(values.get("frame_layout") == layout, "native commitment profile: frame layout differs from the frame")
        for key, value in frame["bounds"].items():
            report.require(values.get(key) == value, f"native commitment profile: bound {key} differs from the frame")
        report.require(values.get("output_bytes") == 32 and "BLAKE3" in values.get("algorithm", ""), "native commitment profile: not raw BLAKE3-256")
    for name, width, partial in (("bn254.poseidon.x5-t3.v1", 3, 57), ("bn254.poseidon.x5-t6.v1", 6, 60)):
        profile = profiles.get(name)
        if profile is None:
            report.error(f"semantic profiles: the corrected BN254 profile {name} is missing")
            continue
        values = profile_reference.parameter_map(profile)
        owner = f"profile {name}"
        report.require(
            (values.get("width"), values.get("full_rounds"), values.get("partial_rounds")) == (width, poseidon_reference.FULL_ROUNDS, partial),
            f"{owner}: width or round numbers differ from the frozen correction",
        )
        report.require(
            values.get("partial_rounds") == poseidon_reference.PARTIAL_ROUNDS_BY_WIDTH[width],
            f"{owner}: selected profile and canonical owner round counts differ",
        )
        report.require(values.get("capacity") == 1 and values.get("rate") == width - 1, f"{owner}: the mode has no single capacity coordinate")
        constants, mds = generated_tables(width, partial)
        digest = hashlib.sha3_256()
        for row in list(constants) + list(mds):
            for value in row:
                digest.update(value.to_bytes(32, "big"))
        report.require(values.get("tables_sha3_256") == digest.hexdigest(), f"{owner}: table digest differs from the regenerated tables")
        report.require(values.get("first_round_constant_be") == constants[0][0].to_bytes(32, "big").hex(), f"{owner}: first round constant differs")
        report.require(values.get("round_constants") == len(constants) * width, f"{owner}: constant count differs")
        report.require(values.get("field_modulus_be") == poseidon_reference.BN254_FR.to_bytes(32, "big").hex(), f"{owner}: modulus differs")
        first = poseidon_reference.permute(list(range(width)), constants, mds)[0].to_bytes(32, "big").hex()
        vector = values.get("vector_permutation_0_1_2_be" if width == 3 else "vector_permutation_0_to_5_be")
        report.require(vector == first, f"{owner}: permutation vector differs from the regenerated permutation")
        tag = (2 if width == 3 else 6) << 64  # the fixed-arity domain tag: arity * 2^64
        modulus = poseidon_reference.BN254_FR
        if width == 3:
            report.require(
                profile.get("checks", {}).get("permutation_0_1_2_coordinate_0_be") == first,
                f"{owner}: the published width-3 reference vector is not reproduced",
            )
            hashed = poseidon_reference.permute([tag, 1, 2], constants, mds)[1]
            report.require(values.get("vector_hash2_1_2_be") == hashed.to_bytes(32, "big").hex(), f"{owner}: corrected hash2 vector differs")
            five = generated_tables(5, 60)
            report.require(
                profile.get("checks", {}).get("width_5_permutation_0_to_4_coordinate_0_be")
                == poseidon_reference.permute(list(range(5)), *five)[0].to_bytes(32, "big").hex(),
                f"{owner}: the published width-5 reference vector is not reproduced",
            )
        else:
            state = poseidon_reference.permute([tag, 1, 2, 3, 4, 5], constants, mds)
            state[1] = (state[1] + 6) % modulus
            hashed = poseidon_reference.permute(state, constants, mds)[1]
            report.require(values.get("vector_hash6_1_to_6_be") == hashed.to_bytes(32, "big").hex(), f"{owner}: corrected hash6 vector differs")
    sets = {entry["id"]: entry for entry in spec["post_quantum"]["parameter_sets"]}
    for name, prefix in (("pq.ml-kem.fips203.v1", "ml-kem"), ("pq.ml-dsa.fips204.v1", "ml-dsa")):
        profile = profiles.get(name)
        if profile is None:
            report.error(f"semantic profiles: the post-quantum profile {name} is missing")
            continue
        values = profile_reference.parameter_map(profile)
        for identifier, entry in sets.items():
            if identifier.startswith(prefix):
                report.require(
                    values.get(identifier.replace("-", "_") + "_bytes") == list(entry["encoded_bytes"].values()),
                    f"profile {name}: encoded sizes of {identifier} differ from the parameter set",
                )
        report.require("FIPS 20" in values.get("standard", ""), f"profile {name}: the standard is not named")
    trapdoor = profiles.get("lantern.trapdoor.falcon512-derived.v1")
    if trapdoor is None:
        report.error("semantic profiles: the Lantern trapdoor profile is missing")
    else:
        labels = profile_reference.parameter_map(trapdoor).get("labels", "")
        report.require("never-fn-dsa" in labels, "Lantern trapdoor profile: it may be labelled FN-DSA")


def check_frozen_transcript(root: Path, spec: dict[str, Any], profiles: dict[str, dict[str, Any]], report: Report) -> None:
    """The frozen shared backend transcript: profile, binding order, tests, goldens and engines."""
    section = spec["semantic_profiles"]
    shared = section.get("shared_transcript", {})
    profile = profiles.get(shared.get("profile"))
    if profile is None or profile.get("kind") != "transcript" or profile.get("status") != "frozen":
        report.error("frozen transcript: the shared transcript names no frozen transcript profile")
        return
    values = profile_reference.parameter_map(profile)
    report.require(values.get("construction") == shared.get("construction"), "frozen transcript: construction name differs from the profile")
    grinding = shared.get("grinding", {})
    report.require(grinding.get("bits") == values.get("grinding_bits"), "frozen transcript: grinding bits differ from the profile")
    report.require(
        (grinding.get("bits") == 0) == (grinding.get("nonce") == "none" and values.get("grinding_nonce") == "none"),
        "frozen transcript: a zero-grinding profile has no nonce and a grinding profile binds one",
    )
    requirements = spec["shared_transcript_requirements"]["binding_order"]
    order = shared.get("binding_order", [])
    report.require([entry.get("order") for entry in order] == [entry["order"] for entry in requirements], "frozen transcript: binding order does not answer every requirement")
    for entry in order:
        owner = f"frozen transcript binding {entry.get('order')}"
        report.require(bool(entry.get("bound")) and bool(entry.get("how")) and bool(entry.get("tests")), f"{owner}: `bound`, `how` or `tests` is missing")
        for test in entry.get("tests", []):
            match = TEST_PATH.match(test)
            if match is None:
                report.error(f"{owner}: test {test!r} is not a backend test path")
                continue
            path = "crates/fastpq_prover/src/backend/" + match["module"].replace("::", "/") + ".rs"
            try:
                report.require(f"fn {match['test']}(" in read_text(root, path), f"{owner}: test {match['test']} is missing from {path}")
            except OSError as error:
                report.error(f"{owner}: {error}")
    statement = shared.get("security_statement", {})
    for field in ("status", "claim_form", "commitments", "classical_rom", "qrom", "hiding", "algebraic_error", "invalidation"):
        report.require(bool(statement.get(field)), f"frozen transcript: security statement `{field}` is missing")
    report.require(statement.get("classical_rom", "").startswith("Conditional"), "frozen transcript: the classical random-oracle claim must stay conditional")
    report.require(statement.get("qrom", "").startswith("Open"), "frozen transcript: the quantum random-oracle claim must stay open")
    report.require("pending" in statement.get("status", ""), "frozen transcript: qualification must stay recorded as pending")
    limits = shared.get("work_limits", {})
    report.require(bool(limits.get("bound")) and bool(limits.get("not_bound")), "frozen transcript: the work-limit binding statement is missing")
    answers = shared.get("known_answers", {})
    try:
        tracked = read_text(root, answers.get("fixture", ""))
        report.require(
            tracked == profile_reference.fixture_text(spec),
            f"frozen transcript: {answers.get('fixture')} differs from the known answers the reference computes",
        )
    except (OSError, KeyError, profile_reference.Abort, profile_reference.ProfileError) as error:
        report.error(f"frozen transcript: known answers: {error}")
    goldens = shared.get("goldens", {})
    for field in ("rust_test",):
        site = answers.get(field, {})
        try:
            report.require(f"fn {site.get('test')}(" in read_text(root, site.get("path", "")), f"frozen transcript: test {site.get('test')} is missing")
        except OSError as error:
            report.error(f"frozen transcript: {error}")
    pin = goldens.get("semantic_identity", {})
    try:
        text = read_text(root, pin.get("path", ""))
        report.require(f"fn {pin.get('test')}(" in text, f"frozen transcript: golden test {pin.get('test')} is missing")
        report.require(f'"{profile["identity"]}"' in text, "frozen transcript: the Rust golden does not pin the recorded identity")
        for key in ("quantity_axt", "execution_effect"):
            value = goldens.get("artifact_profile_ids", {}).get(key)
            report.require(
                isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None and f'"{value}"' in text,
                f"frozen transcript: artifact profile id {key} is not pinned by the Rust golden",
            )
    except OSError as error:
        report.error(f"frozen transcript: {error}")
    for path in [goldens.get("descriptor_pin", "")] + list(goldens.get("proof_pins", [])):
        report.require((root / path).is_file(), f"frozen transcript: golden {path!r} is missing")
    try:
        engines = {entry["id"] for entry in json.loads(read_text(root, spec["shared_transcript_requirements"]["engine_inventory"]))["engines"]}
    except (OSError, ValueError, KeyError) as error:
        report.error(f"frozen transcript: engine inventory: {error}")
        engines = set()
    listed = [entry.get("engine") for entry in shared.get("engines", [])]
    report.require(set(listed) == engines and len(listed) == len(set(listed)), f"frozen transcript: engines {sorted(map(str, listed))} differ from the inventory {sorted(engines)}")
    for entry in shared.get("engines", []):
        owner = f"frozen transcript engine {entry.get('engine')}"
        report.require(entry.get("disposition") in TRANSCRIPT_ENGINE_DISPOSITIONS, f"{owner}: unknown disposition")
        report.require(bool(entry.get("owner_tasks")) and bool(entry.get("note")), f"{owner}: owner tasks or note is missing")
    for site in (profile.get("typed_owner", {}), profile.get("public_accessor", {})):
        check_site(root, report, "frozen transcript owner", site)
    try:
        owner_text = read_text(root, profile["typed_owner"]["path"])
        report.require(f'"{values["construction"]}"' in owner_text and f'"{profile["name"]}"' in owner_text, "frozen transcript: the typed owner does not carry the construction and profile names")
    except (OSError, KeyError) as error:
        report.error(f"frozen transcript: typed owner: {error}")


def check_measurement_binding(spec: dict[str, Any], profiles: dict[str, dict[str, Any]], report: Report) -> None:
    """Workloads name their profiles; a measurement under another identity is inapplicable."""
    section = spec["semantic_profiles"]
    binding = section.get("measurement_binding", {})
    for field in ("rule", "final_measurements", "harness_field", "no_reviewer_token"):
        report.require(bool(binding.get(field)), f"measurement binding: `{field}` is missing")
    for workload in spec["workloads"].get("definitions", []):
        owner = f"workload {workload.get('id')}"
        names, pending = workload_profiles(spec, workload)
        report.require(workload.get("profiles") == names, f"{owner}: `profiles` differs from the profiles of its roles: {names}")
        report.require(workload.get("profiles_not_frozen", []) == pending, f"{owner}: `profiles_not_frozen` differs from the pending selections of its roles: {pending}")
        report.require(
            workload.get("profile_set_identity") == workload_profile_set(spec, names),
            f"{owner}: `profile_set_identity` differs from the identity of its ordered profiles",
        )
    for owner, scope, expected, measurement in recorded_measurements(spec):
        report.require(
            measurement.get("measurement_scope") == scope,
            f"{owner}: `measurement_scope` must be {scope!r} in its owning section",
        )
        report.require("profile_binding" not in measurement, f"{owner}: retired `profile_binding` cannot select measurement scope")
        identities = measurement.get("profile_identities")
        if not isinstance(identities, dict):
            report.error(f"{owner}: `profile_identities` is missing; a measurement names the identity of every profile it measured")
            continue
        report.require(
            set(identities) == set(expected),
            f"{owner}: `profile_identities` must name the complete profile set of its scope: {expected}",
        )
        if scope == "bare-primitives":
            report.require(
                bool(measurement.get("scope_note")),
                f"{owner}: a bare-primitive comparison explains its scope in `scope_note`",
            )
            continue
        report.require(bool(expected), f"{owner}: a workload-profile run requires at least one selected profile")
        for name, recorded in identities.items():
            profile = profiles.get(name)
            if profile is None:
                report.error(f"{owner}: names the unknown profile {name!r}")
                continue
            report.require(name in expected, f"{owner}: names profile {name} that its workload does not depend on")
            report.require(
                recorded == profile.get("identity"),
                f"{owner}: inapplicable: it names identity {recorded} of profile {name}, whose identity is now {profile.get('identity')}; "
                "re-measure it or move it to measurement_binding.inapplicable_measurements",
            )
    recorded_ids = {measurement.get("id") for _, _, _, measurement in recorded_measurements(spec)}
    basis = section.get("exploratory_basis", [])
    report.require(bool(basis), "semantic profiles: the exploratory basis of the selections is missing")
    for entry in basis:
        owner = f"exploratory basis of {entry.get('selection')}"
        report.require(bool(entry.get("selection")) and bool(entry.get("use")), f"{owner}: `selection` or `use` is missing")
        source = entry.get("measurement")
        if source is not None:
            report.require(
                source in recorded_ids or source.startswith("specs/"),
                f"{owner}: {source!r} is neither a recorded measurement nor a tracked record",
            )
    for measurement in binding.get("inapplicable_measurements", []):
        owner = f"inapplicable measurement {measurement.get('id')}"
        identities = measurement.get("profile_identities", {})
        report.require(bool(identities), f"{owner}: names no profile identity")
        report.require(
            any(profiles.get(name, {}).get("identity") != recorded for name, recorded in identities.items()),
            f"{owner}: every identity it names is current, so it is applicable and belongs with its workload",
        )


def check(
    root: Path,
    spec: dict[str, Any],
    files: Sequence[str] | None = None,
    derived: dict[str, Any] | None = None,
) -> list[str]:
    """Return every inconsistency between the specification and the tree.

    `files` and `derived` let a caller that already listed and scanned the tree
    reuse those tables; they must come from the same tree and scan rules.
    """
    report = Report()
    report.require(spec.get("schema_version") == SCHEMA_VERSION, "schema_version differs")
    report.require(spec.get("scope") == SCOPE, "scope statement differs")
    report.require(spec.get("task") == "H.1", "task differs")
    for section in (
        "digest_primitives", "digest_roles", "consumers", "scan", "producer_ledger",
        "canonical_native_commitment", "bn254_poseidon", "post_quantum", "workloads",
        "shared_transcript_requirements", "semantic_profiles",
    ):  # fmt: skip
        if section not in spec:
            report.error(f"section `{section}` is missing")
    if report.errors:
        return report.errors
    if files is None:
        files = tree_files(root)
    if derived is None:
        derived = derive(root, spec, files)
    check_primitives(root, spec, derived, report)
    check_scan(spec, derived, report)
    check_consumers(spec, derived, report)
    check_roles(root, spec, derived, report)
    check_producers(spec, derived, report)
    check_canonical(root, spec, report)
    check_poseidon(root, spec, derived, report)
    check_post_quantum(root, spec, derived, files, report)
    check_workloads(root, spec, report)
    check_transcript(root, spec, report)
    check_semantic_profiles(root, spec, report)
    return report.errors


def _encode(value: Any, depth: int) -> str:
    """JSON text with one-space indentation and lists of scalars on one line."""
    if isinstance(value, dict) and value:
        pad = " " * (depth + 1)
        items = [
            f"{pad}{json.dumps(key, ensure_ascii=False)}: {_encode(item, depth + 1)}"
            for key, item in value.items()
        ]
        return "{\n" + ",\n".join(items) + "\n" + " " * depth + "}"
    if isinstance(value, list) and any(isinstance(item, (dict, list)) for item in value):
        pad = " " * (depth + 1)
        return (
            "[\n"
            + ",\n".join(pad + _encode(item, depth + 1) for item in value)
            + "\n"
            + " " * depth
            + "]"
        )
    return json.dumps(value, ensure_ascii=False)


def dump(spec: dict[str, Any]) -> str:
    """Canonical text of the specification."""
    return _encode(spec, 0) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    """Run the check or a maintainer mode."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=ROOT, help="repository root")
    parser.add_argument("--spec", default=DEFAULT_SPEC, help="specification path under the root")
    parser.add_argument("--print-scan", action="store_true", help="print the fresh scan")
    parser.add_argument("--refresh", action="store_true", help="print the refreshed specification")
    parser.add_argument("--write", action="store_true", help="with --refresh, write the file")
    parser.add_argument("--write-candidate-vectors", action="store_true", help="rewrite the candidate frame fixture")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    try:
        spec = json.loads((root / args.spec).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        print(f"{args.spec}: {error}", file=sys.stderr)
        return 1
    if args.write_candidate_vectors:
        fixture = root / spec["canonical_native_commitment"]["frame"]["vectors"]
        fixture.write_text(render_candidate_vectors(spec), encoding="utf-8")
        return 0
    if args.print_scan or args.refresh:
        derived = derive(root, spec, tree_files(root))
        if args.print_scan:
            sys.stdout.write(json.dumps(derived["scan"], indent=1) + "\n")
            return 0
        try:
            text = dump(refreshed(spec, derived))
        except ValueError as error:
            print(f"{args.spec}: {error}", file=sys.stderr)
            return 1
        if args.write:
            (root / args.spec).write_text(text, encoding="utf-8")
        else:
            sys.stdout.write(text)
        return 0
    errors = check(root, spec)
    for error in errors:
        print(error, file=sys.stderr)
    if errors:
        print(f"{args.spec}: {len(errors)} inconsistencies", file=sys.stderr)
        return 1
    producers = sum(len(functions) for functions in spec["producer_ledger"]["production"].values())
    print(
        f"{args.spec}: {len(spec['digest_primitives'])} primitives, {len(spec['digest_roles'])} roles, "
        f"{len(spec['consumers'])} consumers, {len(spec['scan']['files'])} scanned files, "
        f"{producers} production digest producers, "
        f"{len(spec['workloads']['definitions'])} workloads consistent with the tree"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
