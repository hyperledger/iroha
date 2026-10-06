#!/usr/bin/env python3
"""Check the unified end-to-end resource contract against the source.

`specs/zk_resource_contract.json` enumerates every resource bound on the path
SDK admission -> Torii -> queue -> VM -> proposer -> block -> RS16 payload ->
transport/frame/sync -> follower validation -> storage. This script is the
drift guard for that file. It fails when:

* an owner symbol is gone, or its defining expression or value differs from
  the recorded one (the expression is read from the Rust source and evaluated
  here; references to other constants resolve through other verified bounds);
* an enforcement site no longer contains the recorded text or contains it a
  different number of times than recorded (`count`, one when absent), or a site
  is only a bare symbol, a constant definition or a function signature;
* a named test has lost its `#[test]` attribute, is `#[ignore]`d or compiled
  out by a gate that never holds (below), or its file is no longer part of its
  crate (no `mod`, `include!` or `#[path]` that a test build compiles reaches
  it, or `autotests = false` without a `[[test]]` entry);
* a named test is compiled only with Cargo features (a `cfg` gate on the
  test, on an inline module or other block around it, on its file or on a
  declaration between the file and its crate target, or `required-features`
  of the target) and the contract does not record exactly those in
  `features`, or one of them is not a feature of the crate, so the test never
  runs;
* a gate on that way never holds where the test is compiled: `any()`, `false`,
  `not(all())` or `not(true)` at any depth of the predicate, `not(test)`, or a
  predicate that is false with the default features of the crate and the
  recorded ones (`not(feature = "std")` when `std` is a default feature);
* a limit constant, immutable `static` or committed default in a scanned owner
  file or directory is neither a listed bound nor excluded with a reason
  (`completeness`), the defining expression of an excluded limit differs from
  the one its exclusion pins in `exprs`, a listed name is defined a second
  time in its scope;
* in a scope that sets `comparisons` (the four crates on the path): an integer
  constant of any name that the code compares or that the defining expression
  of a scanned limit names (a term of that limit), or a limit-named function
  without parameters that returns an integer (also inside `Option` or as the
  value of a `Result`), is neither listed nor excluded;
  an excluded term does not record under `term_of` exactly the limits whose
  expressions name it, or an exclusion that is no term records one;
  or a literal comparison is neither inside an enforcement site of a listed
  bound nor recorded with a reason under `completeness.literals`, occurs a
  different number of times than recorded, or is recorded and gone. A literal
  comparison is a comparison with `<`, `<=`, `>` or `>=` (also written as a
  method: `.lt`, `.le`, `.gt`, `.ge`), a capping call (`.min`, `.max`,
  `.clamp`, `.take`, `.truncate`), either of the two called as a function,
  bare or behind any path (`cmp::max(a, b)`, `u32::clamp(n, 2, 64)`,
  `PartialOrd::lt(&a, &b)`), or a range tested with `.contains`, that holds
  an integer literal of `literals.minimum` or more: as a whole operand,
  argument or range end (`len > 4096`), as a part of one (`len > MAX + 1024`,
  `len / 2 >= MAX`, `timeout > Duration::from_secs(30)`), or anywhere in the
  receiver of `.min`, `.max`, `.clamp` or a comparison method. The receiver
  is the whole method chain in front of the call, on one line or broken
  across several (`delta.saturating_mul(10_000).saturating_div(n).min(cap)`),
  also when the call takes no argument (`[n, 64].into_iter().max()`).
  The constants a comparison names are read from the same text as its
  literals: both operands, the arguments, that receiver, and the range with
  the value it tests;
* a source whose name looks like a test or fixture file is compiled outside
  test builds and holds a limit that is not classified;
* a
  field of an authoritative typed catalog in the code (`catalogs`: the
  execution-policy digest, the ZK consensus-policy hash, the Nexus
  consensus-policy preimage and the two committed policy structs) is neither
  listed nor excluded, or a catalog binds a field whose name cannot be read;
* a consensus bound names only tests that pin its value or a digest projection
  (`pin_tests`) without the task that owns the missing boundary test;
* a relation between bounds evaluates differently from its recorded
  expectation, under today's values or under a named target profile;
* a bound is classed inconsistently: a validity-affecting bound read from
  node-local configuration must be recorded as a defect with an owning task,
  a consensus bound names a test or the task that owns the test gap, a local
  resource must defer, a local scheduling limit names where it is applied and
  an engineering target is never validity;
* a separately fixed zk-X509 bound differs from the value the delivery plan
  keeps (`FIXED_BOUNDS` below is the independent copy), a fixed validity bound
  is not classed consensus or a prover time or memory bound is;
* a RAM-LFE budget is given a number while one of its inputs is still open,
  or stays open after every input is known, or an open input or a shape bound
  is used by no budget;
* a stage has neither an exact and one-over test nor a task that owns the gap,
  or the deferral and deterministic-rejection behaviors name no test;
* an open item names a task the delivery graph does not contain, or a task
  the graph marks `implemented` still has open items here;
* a reason, note or description cites a bound id this contract does not have.

Expression reading is textual. It finds one definition by name and kind
(`const`, `fn`, `field`, `arm`) after its anchors and evaluates integer
arithmetic only. It is a source regression guard, not a Rust parser or a
substitute for the Rust tests the contract names. A limit is found by its
name (`LIMIT_NAME`) in every scope, and by what the code compares in a
`comparisons` scope (see "Limits that their name does not mark" below).
A `static` that holds process state (an atomic, a lock, a once-cell, a cell)
is a counter or a cache, not a limit, and is not scanned; a lazy static of a
plain value (`LazyLock<usize>`) is immutable once computed and is scanned.

Gates are read as text: `test`, `feature = ".."`, `true`, `false`, `all(..)`,
`any(..)` and `not(..)` inside `#[cfg(..)]` and `#![cfg(..)]`, and a `cfg(Q)` that
`#[cfg_attr(P, cfg(Q))]` applies, read as `any(not(P), Q)`. Every other
predicate (`unix`, `target_os = ".."`, `debug_assertions`, a `--cfg` of the
build) is not judged: an item behind one is taken as compiled. An inline
module is a test module when one of its gates holds only in a test build,
however the predicate is ordered (`all(feature = "..", test)`).

What the scan still cannot see, by construction: a limit that reaches its
comparison only through a function argument, a struct field or a local
variable and is neither a limit-named constant nor a constant compared
somewhere by name; a limit a function returns when the function takes
parameters, its name has no limit word or its return type is no integer,
`Option` of one or `Result` of one; a limit computed at run time; a
constant of a non-integer type (a `Duration`, a range) that its name does
not mark; a literal below `literals.minimum` or that is no integer (`0.5`).
Comparisons the scan does not read, for a constant that no name marks as
for a literal: one with `==`, `!=`, `cmp` or `partial_cmp`; a `match`
pattern; a relational operator written without whitespace around it;
checked arithmetic that refuses by underflow (`limit.checked_sub(64)?`);
the receiver of `.take` and `.truncate` (the collection that is cut, as in
`(0..ROWS).take(n)`); what a block yields when the block is the receiver of
a cap or an operand (`match kind { .. }.min(cap)`); the head of a receiver
chain in front of a blank outside brackets (the first arguments of a
turbofish, as in `rows::<A, B>().min(cap)`); a cap or comparison function
called under another name (an alias of `use`); and a constant or literal
further than 600 characters from the operator of its relational comparison.
Outside the `comparisons` scopes every limit that its name does not mark is
unseen. An exclusion pins the text
of its limit's defining expression. In a `comparisons` scope an integer
constant that such an expression names is scanned as a term of the limit; an
associated constant of a type (`Header::SIZE`), a constant of a crate that is
not compared and a value a function computes are not followed. A listed
bound resolves every constant its expression names through another verified
bound (`refs`).

Maintenance. The contract is edited by hand; two modes do the mechanical part:

* `--refresh` rewrites every bound's recorded expression and value from the
  source, recomputes the derived bounds, the closed RAM-LFE budgets and the
  occurrence count of every site that is still present, records the defining
  expression of every excluded limit, the limits every excluded term is part
  of (`term_of`) and the features of every named test, and removes exclusions
  that match nothing any more. It keeps every
  classification, site text, test and relation as written and prints each
  count, pinned expression and feature list it changed and each exclusion it
  removed. Use it after an owner changed on purpose, then review the diff:
  a changed value may break a relation, which the following check reports,
  and a changed excluded limit may no longer fit the reason of its exclusion.
* `--mutate [PATH_PREFIX ...]` writes nothing. It replaces, in memory and one
  at a time, the defining expression of every scanned limit (or of the limits
  below the given prefixes) by another value, and raises every literal of
  every literal comparison of a `comparisons` scope by one, and fails when
  the owner, completeness and site checks report nothing for a change.
* `--test-commands` writes nothing. It prints one cargo command per crate
  target and feature set that runs every Rust test the contract names.
* `--propose` writes nothing. For every scanned limit or catalog field that is
  neither listed nor excluded it prints a bound skeleton with the owner
  expression, the value, candidate comparison sites and candidate tests; for
  every literal comparison that is not recorded it prints the `path`, text
  and count to add to a group of `completeness.literals`; for every site
  whose text is gone it prints the closest lines of the file; and it lists
  stale exclusions. `--propose-for PATH:SYMBOL` prints the same
  skeleton for one constant.

Prerequisites: Python 3.9+ standard library, run from a checkout. No
environment variables are read. Nothing is written without `--refresh`.

Usage:
    python3 scripts/check_zk_resource_contract.py
    python3 scripts/check_zk_resource_contract.py --show      # print every bound
    python3 scripts/check_zk_resource_contract.py --refresh   # rewrite expr, value, counts
    python3 scripts/check_zk_resource_contract.py --propose   # suggest entries, write nothing
    python3 scripts/check_zk_resource_contract.py --mutate    # change every limit in memory
    python3 scripts/check_zk_resource_contract.py --test-commands
"""

from __future__ import annotations

import argparse
import ast
import difflib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "specs" / "zk_resource_contract.json"
GRAPH = ROOT / "specs" / "zk_delivery_graph.json"
SCHEMA = "iroha.zk_resource_contract.v1"

CLASSES = ("consensus", "local_defer", "local_schedule", "engineering_target")
SOURCES = ("committed", "constant", "node_local")
OWNER_KINDS = ("const", "fn", "field", "arm")
STAGES = (
    "sdk",
    "torii",
    "queue",
    "vm",
    "proposer",
    "block",
    "rs16",
    "transport",
    "sync",
    "follower",
    "storage",
)
GROUPS = (
    "proof",
    "attachment",
    "transaction",
    "block",
    "rs16",
    "transport",
    "sync",
    "storage",
    "queue",
    "guest_memory",
    "vm_handles",
    "decoded_scratch",
    "queued_effects",
    "work_budget",
    "x509",
    "ram_lfe",
)
EXPECTATIONS = ("holds", "violated")
# The parts of the RAM-LFE workload a budget must exist for (delivery plan, "Mandatory
# RAM-LFE and phone claims"): what is registered, submitted, evaluated, proved, verified,
# opened by one opener or a threshold of them, and what a validator holds while checking.
WORKLOAD_COMPONENTS = (
    "program",
    "key_registration",
    "request",
    "evaluation",
    "receipt",
    "verification",
    "opening",
    "threshold_opening",
    "validator_scratch",
    "class_affine",
    "class_bounded",
    "class_refresh",
    "leakage",
    "prover",
)
GIB = 1024 * 1024 * 1024
# Independent copy of the bounds the delivery plan keeps fixed ("X509 transport
# holder custody and time"). The contract cannot relax one by editing itself.
FIXED_BOUNDS = {
    "x509.max_proof_bytes": 9_437_184,
    "transaction.max_tx_bytes": 10_485_760,
    "x509.max_crl_age_seconds": 300,
    "x509.max_presentation_window_seconds": 300,
    "x509.prover_target_seconds": 300,
    "x509.prover_peak_rss_bytes": 12 * GIB,
    "x509.prover_address_space_bytes": 32 * GIB,
}
# Bounds measured on an encoded structure state what framing the length includes.
FRAMED_BOUNDS = (
    "transaction.max_tx_bytes",
    "transaction.max_decompressed_bytes",
    "block.max_block_bytes",
    "proof.privacy_max_proof_bytes_per_action",
    "proof.privacy_max_action_bytes",
    "proof.proof_box_max_encoded_bytes",
    "x509.max_proof_bytes",
    "queued_effects.max_output_bytes",
    "attachment.list_max_canonical_frame_bytes",
)
# Fixed bounds every validator decides on: they are consensus validity, with sites and tests.
FIXED_VALIDITY = (
    "x509.max_proof_bytes",
    "transaction.max_tx_bytes",
    "x509.max_crl_age_seconds",
    "x509.max_presentation_window_seconds",
)
# The fixed zk-X509 time and memory bounds are targets and prover-process limits.
FIXED_NON_VALIDITY = (
    "x509.prover_target_seconds",
    "x509.prover_peak_rss_bytes",
    "x509.prover_address_space_bytes",
)
# Names that mark a constant as a limit for the completeness scan.
LIMIT_NAME = re.compile(
    r"(?:^|_)(?:MAX|MAXIMUM)(?:_|$)|LIMIT|BUDGET|CEILING|OVERHEAD|RESERVE"
    r"|(?:^|_)CAP(?:ACITY)?(?:_|$)"
)
CONST_DEFINITION = re.compile(
    r"(?:^|[{;])[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?const[ \t]+([A-Z][A-Z0-9_]*)[ \t]*:",
    re.MULTILINE,
)
# An immutable `static` is a limit written another way and is scanned like a constant.
# A `static` that holds process state (an atomic, a lock, a once-cell, a cell: counters,
# caches and guards) is not a value anything is compared with and is not scanned. A lazy
# static is immutable once computed: `LazyLock<usize>` is scanned, `LazyLock<Mutex<..>>`
# holds state and is not.
STATIC_DEFINITION = re.compile(
    r"(?:^|[{;])[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?static[ \t]+([A-Z][A-Z0-9_]*)[ \t]*:"
    r"[ \t]*((?:[A-Za-z_][A-Za-z_0-9]*::)*[A-Za-z_][A-Za-z_0-9]*)?"
    r"(?:[ \t]*<[ \t]*((?:[A-Za-z_][A-Za-z_0-9]*::)*[A-Za-z_][A-Za-z_0-9]*))?",
    re.MULTILINE,
)
STATIC_STATE_HOLDER = re.compile(
    r"^(?:Atomic\w+|Mutex|RwLock|OnceLock|OnceCell|LazyLock|Lazy|Cell|RefCell|Condvar)$"
)
STATIC_LAZY_HOLDER = re.compile(r"^(?:LazyLock|Lazy)$")


def _static_holds_state(match: re.Match) -> bool:
    """Whether a `STATIC_DEFINITION` match declares process state and not an immutable value."""
    holder = (match.group(2) or "").rsplit("::", 1)[-1]
    if not STATIC_STATE_HOLDER.match(holder):
        return False
    if STATIC_LAZY_HOLDER.match(holder) and match.group(3):
        return bool(STATIC_STATE_HOLDER.match(match.group(3).rsplit("::", 1)[-1]))
    return True
DEFAULT_FN_DEFINITION = re.compile(
    r"(?:^|[{;}])[ \t]*pub[ \t]+(?:const[ \t]+)?fn[ \t]+([a-z][a-z0-9_]*)[ \t]*\(\s*\)",
    re.MULTILINE,
)
# An inline module: `mod name {` at the start of a line. It is a test module when a `cfg`
# attribute in front of it holds only in test builds (`inline_test_modules`).
INLINE_MODULE = re.compile(
    r"^[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?mod[ \t]+\w+[ \t]*\{", re.MULTILINE
)
# Files a directory scope never scans: test, bench, example and fixture sources.
TEST_FILE = re.compile(
    r"(?:^|/)(?:tests|benches|examples|fixtures)/|_tests?/"
    r"|(?:^|/)(?:tests?|[a-z0-9_]*_tests?|test_[a-z0-9_]*|[a-z0-9_]*fixtures?[a-z0-9_]*)\.rs$"
)
# The typed catalogs every contract checks against the source.
REQUIRED_CATALOGS = (
    "execution_policy_digest_v1",
    "zk_consensus_policy_hash",
    "nexus_consensus_policy_v1",
    "execution_output_policy_v1",
    "fastpq_source_policy_v1",
)
CATALOG_FORMS = ("policy_push", "zk_policy_put", "struct_tree")
TEST_ATTRIBUTE = re.compile(r"#\[\s*(?:tokio\s*::\s*)?test\b")
IGNORE_ATTRIBUTE = re.compile(r"#\[\s*(?:ignore\b|cfg_attr\s*\([^\]]*\bignore\b)")
# What a gate that never holds is written with: `any()` and `false` are never true,
# `all()` and `true` always are, and `not(test)` is false where a test is compiled. A
# boolean literal counts only inside a `cfg` or `cfg_attr` attribute (`cfg(false)`,
# `cfg(all(test, not(true)))`). A text without one of them holds no gate that `cfg_never`
# can decide (a quick test before the attributes are read).
CFG_CONSTANT = re.compile(
    r"\b(?:any|all)\s*\(\s*\)|\bnot\s*\(\s*test\s*\)"
    r"|\bcfg(?:_attr)?\s*\([^\]]*?\b(?:false|true)\b"
)
CFG_ATTRIBUTE = re.compile(r"#!?\[\s*(cfg|cfg_attr)\s*\(")
PYTHON_SKIP = re.compile(r"@\s*(?:pytest\.mark\.(?:skip|skipif|xfail)|unittest\.skip)")
# A site that is one whole constant or static item, or one function signature.
CONST_ITEM = re.compile(
    r"(?:pub(?:\([^)]*\))?\s+)?(?:const|static)\s+\w+\s*:\s*[^=]+=.*", re.DOTALL
)
FN_SIGNATURE = re.compile(
    r"(?:pub(?:\([^)]*\))?\s+)?(?:(?:const|async|unsafe)\s+)*fn\s+\w+\s*(?:<[^({]*>)?\s*"
    r"\([^{]*(?:\{\s*)?"
)

LINE_COMMENT = re.compile(r"//[^\n]*")
INT_LITERAL = re.compile(
    r"\b(0x[0-9a-fA-F_]+|[0-9][0-9_]*)(?:_?(?:u8|u16|u32|u64|u128|usize|i32|i64))?\b"
)
PATH = re.compile(r"[A-Za-z_][A-Za-z_0-9]*(?:::[A-Za-z_][A-Za-z_0-9]*)*")
CAST = re.compile(r"\bas\s+(?:u8|u16|u32|u64|u128|usize|i32|i64)\b")
POW = re.compile(r"(\d+)\s*\.\s*pow\s*\(\s*(\d+)\s*\)")
METHOD_GET = re.compile(r"\.\s*get\s*\(\s*\)")
EXPECT = re.compile(r"\.\s*(?:expect\s*\(\s*\"[^\"]*\"\s*\)|unwrap\s*\(\s*\))")
WRAPPERS = re.compile(
    r"\b(?:nonzero_ext::nonzero!|nonzero!|Bytes|u64::from|u32::from|usize::from"
    r"|NonZeroUsize::new|NonZeroU64::new|NonZeroU32::new)\s*\("
)
EMPTY_CALL = re.compile(r"\(\s*\)")
ID = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+")


class ContractError(Exception):
    """One reportable inconsistency."""


def normalize(text: str) -> str:
    """Drop line comments and collapse whitespace."""
    return " ".join(LINE_COMMENT.sub("", text).split())


def _after_anchor(source: str, owner: dict, where: str) -> str:
    """Return the source after the owner's anchors, applied in order."""
    anchors = owner.get("anchor")
    if anchors is None:
        return source
    if isinstance(anchors, str):
        anchors = [anchors]
    for anchor in anchors:
        position = source.find(anchor)
        if position < 0:
            raise ContractError(f"{where}: anchor {anchor!r} is not in {owner['path']}")
        source = source[position + len(anchor) :]
    return source


def extract_expression(source: str, owner: dict, where: str) -> str:
    """Return the normalized defining expression of `owner` in `source`."""
    kind = owner["kind"]
    symbol = re.escape(owner["symbol"])
    scope = _after_anchor(source, owner, where)
    if kind == "const":
        pattern = rf"\bconst\s+{symbol}\s*:\s*[^=;]+?=\s*(?P<expr>.*?);"
    elif kind == "fn":
        pattern = rf"\bfn\s+{symbol}\s*\([^)]*\)\s*->\s*[^{{;]+\{{(?P<expr>.*?)\}}"
    elif kind == "field":
        pattern = rf"\b{symbol}\s*:\s*(?P<expr>[^,\n}}]+)[,}}\n]"
    elif kind == "arm":
        pattern = rf"{symbol}\s*=>\s*(?P<expr>[^,\n]+),"
    else:
        raise ContractError(f"{where}: unknown owner kind {kind!r}")
    match = re.search(pattern, scope, re.DOTALL)
    if match is None:
        raise ContractError(
            f"{where}: {kind} `{owner['symbol']}` is not defined in {owner['path']}"
        )
    return normalize(match.group("expr"))


_BINARY = {
    ast.Add: lambda a, b: a + b,
    ast.Sub: lambda a, b: a - b,
    ast.Mult: lambda a, b: a * b,
    ast.FloorDiv: lambda a, b: a // b,
    ast.Mod: lambda a, b: a % b,
    ast.LShift: lambda a, b: a << b,
    ast.RShift: lambda a, b: a >> b,
    ast.Pow: lambda a, b: a**b,
}
_COMPARE = {
    ast.LtE: lambda a, b: a <= b,
    ast.Lt: lambda a, b: a < b,
    ast.GtE: lambda a, b: a >= b,
    ast.Gt: lambda a, b: a > b,
    ast.Eq: lambda a, b: a == b,
    ast.NotEq: lambda a, b: a != b,
}
_FUNCTIONS = {
    "min": min,
    "max": max,
    "ceil_div": lambda a, b: -(-a // b),
}


def _evaluate(node: ast.AST, where: str):
    if isinstance(node, ast.Expression):
        return _evaluate(node.body, where)
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _BINARY:
        return _BINARY[type(node.op)](
            _evaluate(node.left, where), _evaluate(node.right, where)
        )
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        return -_evaluate(node.operand, where)
    if isinstance(node, ast.BoolOp):
        values = [_evaluate(value, where) for value in node.values]
        return all(values) if isinstance(node.op, ast.And) else any(values)
    if isinstance(node, ast.Compare):
        left = _evaluate(node.left, where)
        for operator, right_node in zip(node.ops, node.comparators):
            right = _evaluate(right_node, where)
            if type(operator) not in _COMPARE or not _COMPARE[type(operator)](left, right):
                if type(operator) not in _COMPARE:
                    raise ContractError(f"{where}: unsupported comparison")
                return False
            left = right
        return True
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in _FUNCTIONS
        and not node.keywords
    ):
        return _FUNCTIONS[node.func.id](*[_evaluate(arg, where) for arg in node.args])
    raise ContractError(f"{where}: unsupported expression element {ast.dump(node)[:60]}")


def safe_eval(text: str, where: str):
    """Evaluate integer arithmetic, comparisons, `and`/`or`, min, max, ceil_div."""
    try:
        tree = ast.parse(text, mode="eval")
    except SyntaxError as error:
        raise ContractError(f"{where}: cannot parse {text!r}: {error.msg}") from None
    return _evaluate(tree, where)


def _literal(text: str) -> int:
    digits = text.replace("_", "")
    return int(digits, 16) if digits.lower().startswith("0x") else int(digits, 10)


def evaluate_rust(expression: str, refs: dict, values: dict, where: str) -> int:
    """Evaluate a Rust integer constant expression.

    `refs` maps a referenced path (as written, or its last segment) to the id
    of the bound that owns it; `values` holds the verified value of each id.
    """
    text = CAST.sub("", expression)
    text = EXPECT.sub("", text)
    text = METHOD_GET.sub("", text)
    text = WRAPPERS.sub("(", text)
    text = EMPTY_CALL.sub("", text)
    text = INT_LITERAL.sub(lambda match: str(_literal(match.group(1))), text)
    text = POW.sub(r"(\1 ** \2)", text)

    def resolve(match: re.Match) -> str:
        path = match.group(0)
        target = refs.get(path, refs.get(path.rsplit("::", 1)[-1]))
        if target is None:
            raise ContractError(
                f"{where}: `{path}` in `{expression}` has no entry in `refs`"
            )
        if target not in values:
            raise ContractError(f"{where}: `{path}` refers to unverified bound {target}")
        return str(values[target])

    text = PATH.sub(resolve, text)
    text = text.replace("/", "//")
    if not re.fullmatch(r"[0-9\s+\-*/()<>]*", text) or not text.strip():
        raise ContractError(f"{where}: `{expression}` is not integer arithmetic")
    value = safe_eval(text, where)
    if type(value) is not int:
        raise ContractError(f"{where}: `{expression}` is not an integer")
    return value


def evaluate_relation(expression: str, values: dict, where: str):
    """Evaluate a relation or formula over bound ids."""

    def resolve(match: re.Match) -> str:
        identifier = match.group(0)
        if identifier not in values:
            raise ContractError(f"{where}: unknown or open bound `{identifier}`")
        return str(values[identifier])

    return safe_eval(ID.sub(resolve, expression), where)


_SOURCES: dict = {}
# Source texts that stand in for a file during one check. Only the in-memory mutation
# sweep sets them; nothing is written to disk.
_OVERRIDES: dict = {}


def _read(root: Path, relative: str, where: str) -> str:
    """Read one source file; a file is read once per size and modification time."""
    if relative in _OVERRIDES:
        return _OVERRIDES[relative]
    path = root / relative
    if not path.is_file():
        raise ContractError(f"{where}: {relative} does not exist")
    stat = path.stat()
    key = (str(path), stat.st_mtime_ns, stat.st_size)
    if key not in _SOURCES:
        _SOURCES[key] = path.read_text(encoding="utf-8")
    return _SOURCES[key]


def _override_for(file: Path) -> str | None:
    """The in-memory text that stands in for `file` during this check, if any."""
    if not _OVERRIDES:
        return None
    name = file.as_posix()
    for relative, text in _OVERRIDES.items():
        if name.endswith("/" + relative):
            return text
    return None


class _TextMemo:
    """Results computed from source texts, found by the text itself.

    An entry is keyed by the text, never by its length and hash, so two different texts
    cannot share a result. The oldest half of the texts is dropped beyond `capacity`.
    `forget` drops one text and every text derived from it (its copy without inline
    test modules); the in-memory mutation sweep calls it after each change, so mutated
    copies of large files do not accumulate.
    """

    def __init__(self, capacity: int) -> None:
        self._slots: dict = {}
        self._capacity = capacity

    def get(self, text: str, key, compute):
        """The result recorded for `text` under `key`, computed on first use."""
        slot = self._slots.get(text)
        if slot is None:
            if len(self._slots) >= self._capacity:
                for stale in list(self._slots)[: self._capacity // 2]:
                    del self._slots[stale]
            slot = self._slots[text] = {}
        if key not in slot:
            slot[key] = compute()
        return slot[key]

    def derive(self, text: str, key, compute) -> str:
        """Like `get` for a result that is itself a text: `forget(text)` drops it too."""
        derived = self.get(text, key, compute)
        self._slots[text].setdefault(_TextMemo, set()).add(derived)
        return derived

    def forget(self, text: str) -> None:
        """Drop everything recorded for `text` and for the texts derived from it."""
        slot = self._slots.pop(text, None)
        for derived in (slot or {}).get(_TextMemo, ()):
            if derived is not text:
                self.forget(derived)

    def __len__(self) -> int:
        return len(self._slots)


_TEXTS = _TextMemo(16384)


def _normalized(text: str) -> str:
    """`normalize` of a whole source file, computed once."""
    return _TEXTS.get(text, "normalized", lambda: normalize(text))


# Everything in a Rust source that is not code: comments, string literals (raw ones
# included) and character literals. A lifetime (`'a`) has no closing quote and is code.
_NON_CODE = re.compile(
    r"//[^\n]*"
    r"|/\*.*?\*/"
    r"|(?<![A-Za-z0-9_])b?r(#*)\".*?\"\1"
    r"|b?\"(?:\\.|[^\"\\])*\""
    r"|b?'(?:\\(?:u\{[0-9a-fA-F_]{1,8}\}|x[0-9a-fA-F]{2}|.)|[^'\\\n])'",
    re.DOTALL,
)
_NOT_NEWLINE = re.compile(r"[^\n]")


def code_mask(source: str) -> str:
    """`source` with every comment, string literal and character literal blanked.

    Each blanked character becomes a space and newlines stay, so an offset in the mask
    is the same offset in the source. Braces, operators and names that remain are code.
    """
    return _NON_CODE.sub(lambda match: _blank(match.group(0)), source)


def source_mask(source: str) -> str:
    """`code_mask` of a whole source file, computed once per text."""
    return _TEXTS.get(source, "code_mask", lambda: code_mask(source))


def _blank(text: str) -> str:
    """`text` with every character but a newline replaced by a space."""
    return " " * len(text) if "\n" not in text else _NOT_NEWLINE.sub(" ", text)


def comment_mask(source: str) -> str:
    """`source` with every comment blanked and every literal kept; offsets are unchanged.

    Unlike dropping everything after `//`, this keeps a string that contains `//`
    (`"https://.."`) whole, so the text can be masked again and searched for literals.
    """

    def blank(match: re.Match) -> str:
        text = match.group(0)
        return _blank(text) if text.startswith("/") else text

    return _NON_CODE.sub(blank, source)


_BRACE = re.compile(r"[{}]")


def _top_level_blocks(source: str) -> tuple:
    """The code mask of `source` and `(open, end)` of every brace block at nesting depth zero."""
    mask = source_mask(source)
    blocks = []
    depth = 0
    opening = 0
    for match in _BRACE.finditer(mask):
        if match.group(0) == "{":
            if depth == 0:
                opening = match.start()
            depth += 1
        elif depth > 0:
            depth -= 1
            if depth == 0:
                blocks.append((opening, match.end()))
    if depth > 0:
        blocks.append((opening, len(mask)))
    return mask, blocks


def enclosing_heads(source: str, position: int) -> list:
    """The header of every brace block of `source` that encloses `position`, outermost first.

    A header is the text between the end of the previous item or block and the opening
    brace: the attributes and the declaration of an inline `mod`, an `impl` or a
    function. Braces inside comments and literals do not open a block.
    """
    mask, blocks = _TEXTS.get(source, "top_level_blocks", lambda: _top_level_blocks(source))
    # Only the top-level block around the position can enclose it: start there.
    low, high = 0, len(blocks)
    while low < high:
        middle = (low + high) // 2
        if blocks[middle][0] < position:
            low = middle + 1
        else:
            high = middle
    if low == 0 or blocks[low - 1][1] <= position:
        return []
    stack: list = []
    for match in _BRACE.finditer(mask, blocks[low - 1][0], position):
        if match.group(0) == "{":
            stack.append(match.start())
        elif stack:
            stack.pop()
    heads = []
    for opening in stack:
        start = 1 + max(
            mask.rfind(";", 0, opening), mask.rfind("}", 0, opening), mask.rfind("{", 0, opening)
        )
        heads.append(LINE_COMMENT.sub("", source[start:opening]))
    return heads


def _require(record: dict, keys: tuple, where: str) -> None:
    missing = [key for key in keys if key not in record]
    if missing:
        raise ContractError(f"{where}: missing {', '.join(missing)}")


def _definition_only(site: dict, owner: dict | None = None) -> bool:
    """Whether `site` names no comparison or application of a bound.

    A bare symbol, one constant or static item (the owner's or any other, such as an
    alias) and one function signature prove nothing about enforcement: removing the
    real comparison would leave them in place. A constant item that is a compile-time
    assertion does compare and is accepted. With `owner`, the owner's own definition
    in its file is rejected in every form the checker reads it.
    """
    text = normalize(site["contains"])
    if PATH.fullmatch(text.strip(" ,;.")):
        return True
    if (
        CONST_ITEM.fullmatch(text)
        and ";" not in text.rstrip("; ")
        and "assert" not in text
    ):
        return True
    if FN_SIGNATURE.fullmatch(text):
        return True
    if owner is None or site["path"] != owner["path"]:
        return False
    symbol = re.escape(owner["symbol"])
    return bool(
        re.search(rf"\bconst\s+{symbol}\s*:", text)
        or re.search(rf"\bfn\s+{symbol}\s*\(\s*\)", text)
        or re.fullmatch(rf"{symbol}\s*(?::|=>).*", text)
    )


def test_problem(
    source: str,
    path: str,
    name: str,
    macro: str | None = None,
    macro_source: str | None = None,
) -> str | None:
    """Return why `name` is not a test that runs in `source`, or None when it is.

    `macro` names a `macro_rules!` test generator (for example `state_test`), for a test
    written as `state_test! { sync name ... }` or `world_test!(name { ... })`. The
    generator is defined in the same file, or in the file whose text is `macro_source`
    when the test file is an `include!` of it.
    """
    return _TEXTS.get(
        source,
        ("test_problem", path.endswith(".py"), name, macro, macro_source),
        lambda: _test_problem(source, path, name)
        if macro is None
        else _macro_test_problem(source, name, macro, macro_source),
    )


def _macro_test_problem(
    source: str, name: str, macro: str, macro_source: str | None = None
) -> str | None:
    """A test generated by a `macro_rules!` whose arms carry `#[test]`."""
    generator = re.escape(macro)
    defining = source if macro_source is None else macro_source
    definition = re.search(rf"\bmacro_rules!\s*{generator}\s*\{{", defining)
    if definition is None:
        return f"names the test macro `{macro}!`, which is not defined for"
    end = _block_end(defining, definition.end() - 1)
    body = defining[definition.end() : end if end > 0 else len(defining)]
    if not TEST_ATTRIBUTE.search(body):
        return f"names `{macro}!`, which generates no `#[test]` in"
    if IGNORE_ATTRIBUTE.search(body):
        return f"names `{macro}!`, which generates an `#[ignore]`d test in"
    invocation = rf"\b{generator}!\s*[\{{(]\s*(?:[a-z_]+\s+)?{re.escape(name)}\b"
    if not re.search(invocation, source):
        return "is not in"
    return None


def _named_test_problem(root: Path, test: dict, where: str) -> str | None:
    """`test_problem` for one test record of the contract."""
    macro_source = (
        _read(root, test["macro_path"], where) if test.get("macro_path") else None
    )
    return test_problem(
        _read(root, test["path"], where),
        test["path"],
        test["name"],
        test.get("macro"),
        macro_source,
    )


def _test_problem(source: str, path: str, name: str) -> str | None:
    escaped = re.escape(name)
    if path.endswith(".py"):
        match = re.search(rf"^([ \t]*)def\s+{escaped}\s*\(", source, re.MULTILINE)
        if match is None:
            return "is not in"
        lines = source[: match.start()].splitlines()
        while lines and lines[-1].strip().startswith("@"):
            if PYTHON_SKIP.search(lines.pop()):
                return "is skipped in"
        return None
    found = False
    for match in re.finditer(rf"\bfn\s+{escaped}\s*\(", source):
        found = True
        # The item header: everything after the previous item or block ends.
        head = LINE_COMMENT.sub("", source[max(0, match.start() - 6000) : match.start()])
        head = head[max(head.rfind("}"), head.rfind(";"), head.rfind("{")) + 1 :]
        if not TEST_ATTRIBUTE.search(head):
            continue
        if IGNORE_ATTRIBUTE.search(head):
            return "is `#[ignore]`d in"
        gate = cfg_never(head, True)
        if gate is not None:
            return f"is compiled out by `#[cfg({gate})]` in"
        # An inline module (or any other block) around the test that is never compiled.
        for outer in enclosing_heads(source, match.start()):
            gate = cfg_never(outer, True)
            if gate is not None:
                return f"is inside a block compiled out by `#[cfg({gate})]` in"
        return None
    return "has no `#[test]` attribute in" if found else "is not in"


_REACHABLE: dict = {}
_REFERENCES: dict = {}
_MANIFESTS: dict = {}
_CODE: dict = {}
_KNOWN_REFERRERS: dict = {}
_DECLARES: dict = {}


def _code(file: Path) -> str:
    """The text of `file` with its comments blanked; read once per size and modification time.

    Offsets are those of the file and literals are kept (`comment_mask`), so a position
    found in this text can be given to `enclosing_heads`. A text that stands in for the
    file during this check (`_OVERRIDES`) is read instead.
    """
    override = _override_for(file)
    if override is not None:
        return _TEXTS.derive(override, "code", lambda: comment_mask(override))
    stat = file.stat()
    key = (str(file), stat.st_mtime_ns, stat.st_size)
    if key not in _CODE:
        _CODE[key] = comment_mask(file.read_text(encoding="utf-8"))
    return _CODE[key]


def _crate_of(root: Path, file: Path) -> Path | None:
    """The nearest directory at or below `root` that holds the `Cargo.toml` of `file`."""
    directory = file.parent
    while True:
        key = str(directory)
        if key not in _MANIFESTS:
            _MANIFESTS[key] = (directory / "Cargo.toml").is_file()
        if _MANIFESTS[key]:
            return directory
        if directory == root or root not in directory.parents:
            return None
        directory = directory.parent


def _crate_references(crate: Path) -> dict:
    """Every `include!("..")` and `#[path = ".."]` in the Rust files of `crate`.

    Maps the resolved target to the files that name it. A reference behind a gate that
    holds in no build (`cfg_never`) does not count. Built at most once per run.
    """
    key = str(crate)
    if key not in _REFERENCES:
        found: dict = {}
        for file in sorted(crate.rglob("*.rs")):
            if "target" in file.relative_to(crate).parts:
                continue
            raw = _override_for(file)
            if raw is None:
                raw = file.read_text(encoding="utf-8")
            if "include!" not in raw and "path" not in raw:
                continue
            # A file that may hold a gate that never holds is read with its comments
            # blanked in place, so a reference can be placed among its blocks.
            compiled_out = CFG_CONSTANT.search(raw) is not None
            text = comment_mask(raw) if compiled_out else LINE_COMMENT.sub("", raw)
            for match in re.finditer(
                r"(?:include!\s*\(\s*|#\[\s*path\s*=\s*)\"([^\"]+\.rs)\"", text
            ):
                if compiled_out and (
                    cfg_never(_item_head(text, match.start(), 160)) is not None
                    or any(
                        cfg_never(outer) is not None
                        for outer in enclosing_heads(text, match.start())
                    )
                ):
                    continue
                target = (file.parent / match.group(1)).resolve()
                found.setdefault(str(target), []).append(file)
        _REFERENCES[key] = found
    return _REFERENCES[key]


def _referrers_by_path(crate: Path, file: Path) -> list:
    """The files of `crate` that `include!` or `#[path]` the file.

    The answer of an earlier run is reused while every file that gave it is unchanged;
    otherwise the crate is read again, so a removed reference is always noticed.
    """
    key = str(file.resolve())
    known = _KNOWN_REFERRERS.get(key)
    if known and all(
        referrer.is_file() and referrer.stat().st_mtime_ns == modified
        for referrer, modified in known
    ):
        return [referrer for referrer, _ in known]
    referrers = _crate_references(crate).get(key, [])
    if referrers:
        _KNOWN_REFERRERS[key] = [(referrer, referrer.stat().st_mtime_ns) for referrer in referrers]
    else:
        _KNOWN_REFERRERS.pop(key, None)
    return referrers


def _declares_module(file: Path, name: str) -> bool:
    """Whether `file` declares `mod name;` (or an inline `mod name {`) that a test build compiles."""
    if not file.is_file():
        return False
    stat = file.stat()
    key = (str(file), stat.st_mtime_ns, stat.st_size, name, _override_for(file))
    if key not in _DECLARES:
        text = _code(file)
        _DECLARES[key] = False
        compiled_out = CFG_CONSTANT.search(text) is not None
        for match in re.finditer(rf"\bmod\s+{re.escape(name)}\s*[;{{]", text):
            head = text[max(0, match.start() - 200) : match.start()]
            head = head[max(head.rfind(";"), head.rfind("}"), head.rfind("{")) + 1 :]
            # `#[path = ".."] mod name;` names another file; `_referrers_by_path` reads it.
            if (
                not re.search(r"#\[\s*path\b", head)
                and not (
                    compiled_out
                    and (
                        cfg_never(head, True) is not None
                        # A declaration inside an inline module that is never compiled.
                        or any(
                            cfg_never(outer, True) is not None
                            for outer in enclosing_heads(text, match.start())
                        )
                    )
                )
            ):
                _DECLARES[key] = True
                break
    return _DECLARES[key]


def _reaches_crate_root(crate: Path, file: Path, seen: frozenset) -> bool:
    """Whether a chain of `mod`, `include!` and `#[path]` joins `file` to a crate target.

    Targets are `src/lib.rs`, `src/main.rs`, `src/bin/*`, a path the manifest names, and
    a top-level file of `tests/`, `benches/` or `examples/` unless the manifest turns
    automatic discovery of that directory off.
    """
    key = str(file)
    if key in _REACHABLE:
        return _REACHABLE[key]
    if key in seen:
        return False
    seen = seen | {key}
    parts = file.relative_to(crate).parts
    manifest = (crate / "Cargo.toml").read_text(encoding="utf-8")
    automatic = {"tests": "autotests", "benches": "autobenches", "examples": "autoexamples"}
    if parts[0] == "src" and (
        (len(parts) == 2 and parts[1] in ("lib.rs", "main.rs"))
        or (len(parts) == 3 and parts[1] == "bin")
    ):
        result = True
    elif f'"{"/".join(parts)}"' in manifest:
        result = True
    elif (
        parts[0] in automatic
        and (len(parts) == 2 or (len(parts) == 3 and parts[2] == "main.rs"))
        and not re.search(rf"^\s*{automatic[parts[0]]}\s*=\s*false", manifest, re.MULTILINE)
    ):
        result = True
    else:
        referrers: list = []
        module, directory = file.stem, file.parent
        if file.name == "mod.rs":
            module, directory = directory.name, directory.parent
        # `mod name;` in the parent module file, or in an ancestor for a nested inline module.
        ancestor = directory
        for _ in range(4):
            if crate not in (ancestor, *ancestor.parents):
                break
            for parent in (
                ancestor / "mod.rs",
                ancestor.parent / f"{ancestor.name}.rs",
                ancestor / "lib.rs",
                ancestor / "main.rs",
            ):
                if parent != file and _declares_module(parent, module):
                    referrers.append(parent)
            ancestor = ancestor.parent
        result = any(_reaches_crate_root(crate, referrer, seen) for referrer in referrers)
        if not result:
            # Otherwise an `include!` or a `#[path]` somewhere in the crate names the file.
            result = any(
                referrer != file and _reaches_crate_root(crate, referrer, seen)
                for referrer in _referrers_by_path(crate, file)
            )
    _REACHABLE[key] = result
    return result


def unreachable_test_file(root: Path, relative: str) -> bool:
    """Whether the Rust test file is in a crate and no module path of that crate reaches it.

    A file without a crate manifest above it (a scratch source) is not judged.
    """
    if not relative.endswith(".rs"):
        return False
    file = root / relative
    crate = _crate_of(root, file)
    if crate is None:
        return False
    return not _reaches_crate_root(crate, file, frozenset())


def _cfg_node(predicate: str) -> tuple:
    """One `cfg` predicate as a tree.

    `("test",)`, `("feature", name)`, `("all", parts)`, `("any", parts)`, `("not", part)`,
    or `("other", text)` for every predicate this checker does not judge (`unix`,
    `target_os = ".."`, `debug_assertions`, a `--cfg` of the build). The boolean
    literals are read as the empty groups they equal: `false` as `any()`, which never
    holds, and `true` as `all()`, which always does.
    """
    predicate = predicate.strip()
    if predicate == "test":
        return ("test",)
    if predicate in ("false", "true"):
        return ("any" if predicate == "false" else "all", [])
    feature = re.fullmatch(r"feature\s*=\s*\"([^\"]+)\"", predicate)
    if feature:
        return ("feature", feature.group(1))
    call = re.fullmatch(r"(all|any|not)\s*\((.*)\)", predicate, re.DOTALL)
    if call is None:
        return ("other", predicate)
    parts = [_cfg_node(part) for part in _split_top_level(call.group(2)) if part.strip()]
    if call.group(1) == "not":
        return ("not", parts[0]) if len(parts) == 1 else ("other", predicate)
    return (call.group(1), parts)


def _cfg_value(node: tuple, test: bool | None, enabled=None, open_features=frozenset()):
    """Whether a `cfg` tree holds: True, False, or None when that is not known.

    `test` is True in a test build and None when the build is not known. `enabled` is the
    set of Cargo features that are on (every other feature is off), or None when the
    features are not known; a feature in `open_features` is not known either. `any()` is
    false and `all()` is true. Every other predicate (`("other", ..)`) is not known.
    """
    kind = node[0]
    if kind == "test":
        return test
    if kind == "feature":
        if enabled is None or node[1] in open_features:
            return None
        return node[1] in enabled
    if kind == "not":
        inner = _cfg_value(node[1], test, enabled, open_features)
        return None if inner is None else not inner
    if kind in ("all", "any"):
        values = [_cfg_value(part, test, enabled, open_features) for part in node[1]]
        decides = kind == "any"
        if decides in values:
            return decides
        return None if None in values else not decides
    return None


def _node_requirement(node: tuple) -> set:
    """`_cfg_requirement` of a parsed predicate."""
    kind = node[0]
    if kind == "feature":
        return {node[1]}
    if kind == "all":
        return set().union(*(_node_requirement(part) for part in node[1]))
    if kind == "any":
        # An alternative that never holds where a test is compiled (`not(test)`, `any()`)
        # is none: `any(not(test), feature = "x")` requires x.
        parts = [
            _node_requirement(part) for part in node[1] if _cfg_value(part, True) is not False
        ]
        if not parts or any(not part for part in parts):
            return set()
        return {"|".join(sorted("+".join(sorted(part)) for part in parts))}
    return set()


def _cfg_requirement(predicate: str) -> set:
    """The features one `cfg` predicate requires where a test is compiled.

    `feature = "x"` requires x; `all(..)` requires what every part requires; `any(..)`
    requires nothing when one alternative that can hold requires nothing
    (`any(test, feature = "x")`) and otherwise the alternatives as one entry (`a|b`);
    `not(..)` and every other predicate (`test`, `target_os = ".."`) require nothing.
    """
    return _node_requirement(_cfg_node(predicate))


def cfg_predicates(text: str) -> list:
    """The predicate of every `cfg` gate among the attributes in `text`.

    `#[cfg(P)]` and `#![cfg(P)]` give P. `#[cfg_attr(P, .., cfg(Q), ..)]` applies
    `cfg(Q)` where P holds and gives `any(not(P), Q)`, at every depth of nesting.
    """
    found = []
    for match in CFG_ATTRIBUTE.finditer(text):
        end = _group_end(text, match.end() - 1, "(", ")")
        if end < 0:
            continue
        inside = text[match.end() : end - 1]
        if match.group(1) == "cfg":
            found.append(inside.strip())
        else:
            found.extend(_cfg_attr_predicates(inside))
    return found


def _cfg_attr_predicates(arguments: str) -> list:
    """The gates a `cfg_attr(P, attribute, ..)` with these arguments applies."""
    parts = [part.strip() for part in _split_top_level(arguments)]
    condition, found = parts[0], []
    for part in parts[1:]:
        inner = re.fullmatch(r"(cfg|cfg_attr)\s*\((.*)\)", part, re.DOTALL)
        if inner is None:
            continue
        gates = [inner.group(2).strip()] if inner.group(1) == "cfg" else _cfg_attr_predicates(inner.group(2))
        found.extend(f"any(not({condition}), {gate})" for gate in gates)
    return found


def cfg_never(text: str, test: bool | None = None) -> str | None:
    """The first `cfg` gate in `text` that never holds, or None.

    With `test` None the gate holds in no build at all (`any()`, `false`,
    `all(test, any())`, `not(all())`, `not(true)`); with `test` True it does not hold
    where a test is compiled either
    (`not(test)`). Features are not known here: `_test_features` judges a gate against
    the features of the command that runs the test.
    """
    if CFG_CONSTANT.search(text) is None:
        return None
    for predicate in cfg_predicates(text):
        if _cfg_value(_cfg_node(predicate), test) is False:
            return " ".join(predicate.split())
    return None


def _cfg_requires_test(predicate: str) -> bool:
    """Whether one `cfg` predicate holds only in a test build.

    `test` does; `all(..)` does when one part does; `any(..)` when every alternative
    does; `not(..)` and every other predicate do not.
    """
    predicate = predicate.strip()
    if predicate == "test":
        return True
    call = re.fullmatch(r"(all|any|not)\s*\((.*)\)", predicate, re.DOTALL)
    if call is None:
        return False
    parts = [
        _cfg_requires_test(part) for part in _split_top_level(call.group(2)) if part.strip()
    ]
    if call.group(1) == "all":
        return any(parts)
    if call.group(1) == "any":
        return bool(parts) and all(parts)
    return False


def cfg_requires_test(text: str) -> bool:
    """Whether a `#[cfg(..)]` or `#![cfg(..)]` attribute in `text` holds only in a test build."""
    for match in re.finditer(r"#!?\[\s*cfg\s*\(", text):
        end = _group_end(text, match.end() - 1, "(", ")")
        if end > 0 and _cfg_requires_test(text[match.end() : end - 1]):
            return True
    return False


_TEST_ONLY: dict = {}
_MANIFEST_TEXT: dict = {}
_MODULE_DECLARATION = re.compile(r"\bmod\s+([A-Za-z_][A-Za-z_0-9]*)\s*[;{]")


def _module_declarations(text: str) -> dict:
    """Module name -> the offsets of every `mod name;` and `mod name {` in `text`."""

    def read() -> dict:
        found: dict = {}
        for match in _MODULE_DECLARATION.finditer(text):
            found.setdefault(match.group(1), []).append(match.start())
        return found

    return _TEXTS.get(text, "module_declarations", read)


def _chain_test_only(crate: Path, file: Path, seen: frozenset) -> bool | None:
    """Whether every chain from `file` to a crate target is compiled only in test builds.

    Follows the chains of `_chain_gates`. A chain is test-only when the file, a
    declaration on it or a block around such a declaration is gated by `cfg(test)`, or
    when it ends in a test, bench or example target. Returns False when one chain
    reaches a library or binary target without such a gate, and None when no chain
    reaches a target (the file is not compiled).
    """
    key = str(file)
    if key in seen or not file.is_file():
        return None
    # A verdict is kept while no source of the crate changes and no text stands in for
    # one of its files. The module graph of a crate has no cycle, so the verdict of a
    # file does not depend on the path that led to it.
    kept = _crate_sources_unchanged(crate)
    if kept and key in _TEST_ONLY:
        return _TEST_ONLY[key]
    verdict = _read_chain_test_only(crate, file, seen | {key})
    if kept:
        _TEST_ONLY[key] = verdict
    return verdict


_CRATE_FINGERPRINTS: dict = {}
# Counts the scans of this process: the sources of a crate are compared with their last
# fingerprint once per scan.
_SCAN_EPOCH = [0]


def _crate_sources_unchanged(crate: Path) -> bool:
    """Whether verdicts recorded for `crate` may be reused in this scan.

    False while a text stands in for a file of the crate. Otherwise the size and
    modification time of every Rust source and of the manifest are compared with the
    last scan, once per scan; when one differs, the verdicts of the crate are dropped.
    """
    name = crate.as_posix()
    if any(name.endswith("/" + "/".join(relative.split("/")[:2])) for relative in _OVERRIDES):
        return False
    known = _CRATE_FINGERPRINTS.get(name)
    if known is not None and known[0] == _SCAN_EPOCH[0]:
        return True
    files = [crate / "Cargo.toml", *crate.rglob("*.rs")]
    fingerprint = hash(
        tuple(sorted((str(file), file.stat().st_mtime_ns, file.stat().st_size) for file in files))
    )
    if known is None or known[1] != fingerprint:
        prefix = name + "/"
        for stale in [key for key in _TEST_ONLY if key.startswith(prefix)]:
            del _TEST_ONLY[stale]
    _CRATE_FINGERPRINTS[name] = (_SCAN_EPOCH[0], fingerprint)
    return True


_RAW: dict = {}


def _raw(file: Path) -> str:
    """The text of `file`, or the text that stands in for it; read once per stat."""
    override = _override_for(file)
    if override is not None:
        return override
    stat = file.stat()
    key = (str(file), stat.st_mtime_ns, stat.st_size)
    if key not in _RAW:
        if len(_RAW) > 8192:
            _RAW.clear()
        _RAW[key] = file.read_text(encoding="utf-8")
    return _RAW[key]


def _file_requires_test(text: str) -> bool:
    """Whether an inner attribute at the head of a file (`#![cfg(test)]`) gates it to tests.

    Inner attributes come before the first item: only the leading blank, comment and
    `#![..]` lines are read, so text further down that looks like one does not count.
    """

    def read() -> bool:
        attributes = []
        open_attribute = False
        for line in text.splitlines():
            stripped = line.strip()
            if open_attribute:
                attributes[-1] += " " + stripped
                open_attribute = "]" not in stripped
            elif stripped.startswith("#!["):
                attributes.append(stripped)
                open_attribute = stripped.count("[") > stripped.count("]")
            elif stripped and not stripped.startswith("//"):
                break
        return cfg_requires_test("\n".join(attributes))

    return _TEXTS.get(text, "file_requires_test", read)


def _read_chain_test_only(crate: Path, file: Path, seen: frozenset) -> bool | None:
    """`_chain_test_only` without its record of earlier verdicts."""
    if _file_requires_test(_raw(file)):
        return True
    parts = file.relative_to(crate).parts
    manifest_key = str(crate)
    if manifest_key not in _MANIFEST_TEXT:
        _MANIFEST_TEXT[manifest_key] = (crate / "Cargo.toml").read_text(encoding="utf-8")
    manifest = _MANIFEST_TEXT[manifest_key]
    relative = "/".join(parts)
    if parts[0] == "src" and (
        (len(parts) == 2 and parts[1] in ("lib.rs", "main.rs")) or (len(parts) == 3 and parts[1] == "bin")
    ):
        return False
    for block in re.split(r"^\[", manifest, flags=re.MULTILINE)[1:]:
        if re.search(rf"^path\s*=\s*\"{re.escape(relative)}\"", block, re.MULTILINE):
            return block.lstrip("[").split("]", 1)[0] in ("test", "bench", "example")
    if parts[0] in ("tests", "benches", "examples") and (
        len(parts) == 2 or (len(parts) == 3 and parts[2] == "main.rs")
    ):
        return True
    module, directory = file.stem, file.parent
    if file.name == "mod.rs":
        module, directory = directory.name, directory.parent
    verdicts = []
    ancestor = directory
    # The inline modules a declaration in `ancestor` must sit in to name this file:
    # `mod a { mod b { mod name; } }` in `x.rs` declares `x/a/b/name.rs`.
    nesting: list = []
    for _ in range(4):
        if crate not in (ancestor, *ancestor.parents):
            break
        for parent in (
            ancestor / "mod.rs",
            ancestor.parent / f"{ancestor.name}.rs",
            ancestor / "lib.rs",
            ancestor / "main.rs",
        ):
            if parent == file or not parent.is_file():
                continue
            parent_text = _code(parent)
            for position in _module_declarations(parent_text).get(module, ()):
                head = _item_head(parent_text, position)
                outer = enclosing_heads(parent_text, position)
                if (
                    cfg_never(head) is not None
                    or re.search(r"#\[\s*path\b", head)
                    or any(cfg_never(block) is not None for block in outer)
                ):
                    continue
                # A module of the same name declared at another level is another file.
                if _inline_module_names(outer) != nesting:
                    continue
                gated = cfg_requires_test(head) or any(cfg_requires_test(block) for block in outer)
                verdicts.append((parent, gated))
        nesting.insert(0, ancestor.name)
        ancestor = ancestor.parent
    for referrer in _referrers_by_path(crate, file):
        if referrer == file:
            continue
        referrer_text = _code(referrer)
        for match in re.finditer(
            r"(?:include!\s*\(\s*|#\[\s*path\s*=\s*)\"([^\"]+\.rs)\"", referrer_text
        ):
            if (referrer.parent / match.group(1)).resolve() != file.resolve():
                continue
            head = _item_head(referrer_text, match.start())
            tail = referrer_text[match.end() : match.end() + 300].split(";", 1)[0]
            outer = enclosing_heads(referrer_text, match.start())
            if any(cfg_never(block) is not None for block in outer):
                continue
            gated = (
                cfg_requires_test(head)
                or cfg_requires_test(tail)
                or any(cfg_requires_test(block) for block in outer)
            )
            verdicts.append((referrer, gated))
    reached = None
    for referrer, gated in verdicts:
        above = True if gated else _chain_test_only(crate, referrer, seen)
        if above is False:
            return False
        if above is True:
            reached = True
    return reached


def _test_only_verdict(root: Path, relative: str) -> bool | None:
    """`_chain_test_only` of one source, read once per check; None also without a crate."""
    file = root / relative
    crate = _crate_of(root, file)
    if crate is None:
        return None
    return _chain_test_only(crate, file, frozenset())


def compiled_outside_tests(root: Path, relative: str) -> bool:
    """Whether a Rust source whose name looks like a test file is production code.

    True when a library or binary target of its crate compiles the file without a
    `cfg(test)` gate on the way (`pub mod lane_fixture;`). A file without a crate
    manifest above it is not judged: its name decides.
    """
    return _test_only_verdict(root, relative) is False


def compiled_only_in_tests(root: Path, relative: str) -> bool:
    """Whether every declaration that reaches a source compiles it only in test builds.

    Such a file (`#[cfg(test)] mod reference;`) holds no production comparison, whatever
    its name. A file without a crate manifest above it is not judged.
    """
    return _test_only_verdict(root, relative) is True


def _inline_module_names(heads: list) -> list:
    """The names of the inline modules among enclosing block headers, outermost first.

    A header that is no `mod name` (an `impl`, a function) yields None in its place, so
    a declaration inside such a block matches no directory nesting.
    """
    names = []
    for head in heads:
        module = re.search(r"\bmod\s+([A-Za-z_][A-Za-z_0-9]*)\s*$", head)
        names.append(module.group(1) if module else None)
    return names


def _block_gates(heads: list) -> list:
    """The `cfg` gates on enclosing blocks (`enclosing_heads`), as predicates."""
    return [predicate for head in heads for predicate in cfg_predicates(head)]


def _item_head(text: str, position: int, window: int = 600) -> str:
    """The attributes in front of the item at `position`: the text after the previous item."""
    head = text[max(0, position - window) : position]
    return head[max(head.rfind(";"), head.rfind("}"), head.rfind("{")) + 1 :]


_MANIFEST_FEATURES: dict = {}


def _manifest_features(crate: Path) -> dict:
    """The `[features]` table of a crate: each feature with the same-crate features it enables."""
    key = str(crate)
    if key not in _MANIFEST_FEATURES:
        manifest = (crate / "Cargo.toml").read_text(encoding="utf-8")
        table = re.search(r"^\[features\]\s*$(.*?)(?=^\[)", manifest + "\n[", re.MULTILINE | re.DOTALL)
        features: dict = {}
        if table:
            for entry in re.finditer(
                r"^([A-Za-z0-9_-]+)\s*=\s*\[(.*?)\]", table.group(1), re.MULTILINE | re.DOTALL
            ):
                features[entry.group(1)] = [
                    name
                    for name in re.findall(r"\"([^\"]+)\"", entry.group(2))
                    if "/" not in name and not name.startswith("dep:")
                ]
        _MANIFEST_FEATURES[key] = features
    return _MANIFEST_FEATURES[key]


def _implied_features(crate: Path, name: str) -> set:
    """Every same-crate feature that enabling `name` enables, `name` included."""
    features = _manifest_features(crate)
    seen = set()
    pending = [name]
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        pending.extend(features.get(current, []))
    return seen


def _target_features(crate: Path, file: Path) -> set:
    """`required-features` of the manifest target whose `path` is `file`."""
    manifest = (crate / "Cargo.toml").read_text(encoding="utf-8")
    relative = file.relative_to(crate).as_posix()
    required: set = set()
    for block in re.split(r"^\[\[", manifest, flags=re.MULTILINE)[1:]:
        block = block.split("\n[", 1)[0]
        if re.search(rf"^path\s*=\s*\"{re.escape(relative)}\"", block, re.MULTILINE):
            listed = re.search(r"^required-features\s*=\s*\[(.*?)\]", block, re.MULTILINE | re.DOTALL)
            if listed:
                required |= set(re.findall(r"\"([^\"]+)\"", listed.group(1)))
    return required


def _chain_gates(crate: Path, file: Path, seen: frozenset) -> tuple | None:
    """The gates on the `mod`, `include!` and `#[path]` chain from `file` to a crate target.

    Follows the same chain as `_reaches_crate_root` and collects the `cfg` gates of every
    declaration on it and of every block around one, the inner `#![cfg(..)]` gates of
    every file on it and the `required-features` of the target. Returns
    `(predicates, required_features)`, or None when no chain reaches a target. A
    declaration behind a gate that never holds where a test is compiled is no chain.
    """
    key = str(file)
    if key in seen or not file.is_file():
        return None
    seen = seen | {key}
    _FEATURE_TRAIL.update((file, crate / "Cargo.toml"))
    text = _code(file)
    own = cfg_predicates("\n".join(re.findall(r"^[ \t]*#!\[[^\n]*", text, re.MULTILINE)))
    parts = file.relative_to(crate).parts
    manifest = (crate / "Cargo.toml").read_text(encoding="utf-8")
    automatic = {"tests": "autotests", "benches": "autobenches", "examples": "autoexamples"}
    is_target = (
        (parts[0] == "src" and len(parts) == 2 and parts[1] in ("lib.rs", "main.rs"))
        or (parts[0] == "src" and len(parts) == 3 and parts[1] == "bin")
        or f'"{"/".join(parts)}"' in manifest
        or (
            parts[0] in automatic
            and (len(parts) == 2 or (len(parts) == 3 and parts[2] == "main.rs"))
            and not re.search(rf"^\s*{automatic[parts[0]]}\s*=\s*false", manifest, re.MULTILINE)
        )
    )
    if is_target:
        return own, _target_features(crate, file)
    module, directory = file.stem, file.parent
    if file.name == "mod.rs":
        module, directory = directory.name, directory.parent
    candidates = []
    ancestor = directory
    for _ in range(4):
        if crate not in (ancestor, *ancestor.parents):
            break
        for parent in (
            ancestor / "mod.rs",
            ancestor.parent / f"{ancestor.name}.rs",
            ancestor / "lib.rs",
            ancestor / "main.rs",
        ):
            if parent == file or not parent.is_file():
                continue
            _FEATURE_TRAIL.add(parent)
            parent_text = _code(parent)
            for match in re.finditer(rf"\bmod\s+{re.escape(module)}\s*[;{{]", parent_text):
                head = _item_head(parent_text, match.start())
                outer = enclosing_heads(parent_text, match.start())
                if (
                    cfg_never(head, True) is None
                    and not re.search(r"#\[\s*path\b", head)
                    and not any(cfg_never(block, True) is not None for block in outer)
                ):
                    candidates.append((parent, cfg_predicates(head) + _block_gates(outer)))
        ancestor = ancestor.parent
    for referrer in _referrers_by_path(crate, file):
        if referrer == file:
            continue
        _FEATURE_TRAIL.add(referrer)
        referrer_text = _code(referrer)
        for match in re.finditer(
            r"(?:include!\s*\(\s*|#\[\s*path\s*=\s*)\"([^\"]+\.rs)\"", referrer_text
        ):
            if (referrer.parent / match.group(1)).resolve() != file.resolve():
                continue
            # The attributes before the reference and, for `#[path]`, up to its `mod`.
            head = _item_head(referrer_text, match.start())
            tail = referrer_text[match.end() : match.end() + 300].split(";", 1)[0]
            outer = enclosing_heads(referrer_text, match.start())
            if any(cfg_never(block, True) is not None for block in (head, tail, *outer)):
                continue
            candidates.append(
                (referrer, cfg_predicates(head) + cfg_predicates(tail) + _block_gates(outer))
            )
    for referrer, declared in candidates:
        above = _chain_gates(crate, referrer, seen)
        if above is not None:
            return own + declared + above[0], above[1]
    return None


# Files read while one feature chain is followed, and the answers they gave.
_FEATURE_TRAIL: set = set()
_TEST_FEATURES: dict = {}


def test_features(root: Path, test: dict, where: str) -> list | None:
    """The features a named Rust test needs to be compiled, smallest set, sorted.

    They come from the `cfg` attributes of the test function, of every inline module (or
    other block) that encloses it, of its file and of every declaration that joins the
    file to its crate, and from `required-features` of its test target. A feature another
    one of the set enables is left out. Returns None for a test that is not Rust, has no
    crate or is generated by a macro. A test whose file no test build compiles, or that a
    gate compiles out under those features, is an error. The answer of an earlier call is
    reused while every
    file that gave it is unchanged and no text stands in for a file (`_OVERRIDES`).
    """
    if not test["path"].endswith(".rs") or test.get("macro"):
        return None
    key = (str(root), test["path"], test["name"])
    known = _TEST_FEATURES.get(key)
    if (
        known is not None
        and not _OVERRIDES
        and all(path.is_file() and path.stat().st_mtime_ns == stamp for path, stamp in known[0])
    ):
        if isinstance(known[1], ContractError):
            raise ContractError(f"{where}: {known[1]}")
        return None if known[1] is None else list(known[1])
    _FEATURE_TRAIL.clear()
    try:
        answer = _test_features(root, test)
    except ContractError as error:
        answer = error
    if not _OVERRIDES:
        _TEST_FEATURES[key] = (
            [(path, path.stat().st_mtime_ns) for path in sorted(_FEATURE_TRAIL) if path.is_file()],
            answer,
        )
    if isinstance(answer, ContractError):
        raise ContractError(f"{where}: {answer}")
    return None if answer is None else list(answer)


def _test_features(root: Path, test: dict) -> list | None:
    where = "features"
    file = root / test["path"]
    crate = _crate_of(root, file)
    if crate is None:
        return None
    _FEATURE_TRAIL.add(file)
    chain = _chain_gates(crate, file, frozenset())
    if chain is None:
        # A declaration reaches the file (`unreachable_test_file` is asked first), but
        # none that a test build compiles: `#[cfg(not(test))] include!("..")`.
        raise ContractError(
            f"test `{test['name']}` is in {test['path']}, which no declaration that a test "
            "build compiles joins to a target of its crate: it never runs"
        )
    predicates, required = list(chain[0]), set(chain[1])
    source = _read(root, test["path"], where)
    for match in re.finditer(rf"\bfn\s+{re.escape(test['name'])}\s*\(", source):
        head = LINE_COMMENT.sub("", source[max(0, match.start() - 6000) : match.start()])
        head = head[max(head.rfind("}"), head.rfind(";"), head.rfind("{")) + 1 :]
        if TEST_ATTRIBUTE.search(head):
            predicates += cfg_predicates(head)
            # The usual gate of a Rust test is on the inline module around it:
            # `#[cfg(all(test, feature = ".."))] mod tests { .. }`.
            predicates += _block_gates(enclosing_heads(source, match.start()))
            break
    for predicate in predicates:
        required |= _cfg_requirement(predicate)
    declared = _manifest_features(crate)
    for entry in sorted(required):
        for name in re.split(r"[|+]", entry):
            if name not in declared:
                raise ContractError(
                    f"test `{test['name']}` in {test['path']} is compiled only with "
                    f"feature `{name}`, which is not a feature of its crate: it never runs"
                )
    minimal = {
        entry
        for entry in required
        if not any(
            other != entry and "|" not in other and entry in _implied_features(crate, other)
            for other in required
        )
    }
    # The command that runs the test turns on the default features and the recorded
    # ones. A gate that is false under exactly those (`not(feature = "std")` with `std`
    # a default feature, `not(test)`, `all(test, any())`) compiles the test out.
    enabled = _implied_features(crate, "default") if "default" in declared else set()
    alternatives = set()
    for entry in minimal:
        if "|" in entry:
            alternatives.update(re.split(r"[|+]", entry))
        else:
            enabled |= _implied_features(crate, entry)
    for predicate in predicates:
        if _cfg_value(_cfg_node(predicate), True, enabled, frozenset(alternatives - enabled)) is False:
            raise ContractError(
                f"test `{test['name']}` in {test['path']} is behind "
                f"`#[cfg({' '.join(predicate.split())})]`, which is false with the default "
                f"features and {sorted(minimal)}: it never runs"
            )
    return sorted(minimal)


def _check_sites(
    root: Path,
    record: dict,
    where: str,
    problems: list,
    owner: dict | None = None,
    refresh: bool = False,
    notes: list | None = None,
) -> None:
    """Check the enforcement sites, tests and observations of one record.

    A site records how many times its text occurs in its file (`count`, one when
    absent): removing one of two identical comparisons is drift. With `refresh` the
    count of a site that is still present is rewritten and reported in `notes`.
    """
    for site in record.get("enforcement", []):
        try:
            _require(site, ("stage", "path", "contains"), where)
            if site["stage"] not in STAGES:
                raise ContractError(f"{where}: unknown stage {site['stage']!r}")
            source = _normalized(_read(root, site["path"], where))
            occurrences = source.count(normalize(site["contains"]))
            if occurrences == 0:
                raise ContractError(
                    f"{where}: {site['path']} no longer contains `{site['contains']}`"
                )
            if _definition_only(site, owner):
                raise ContractError(
                    f"{where}: the site `{site['contains']}` is only a symbol, a "
                    "definition or a function signature; name where the bound is "
                    "compared or applied"
                )
            recorded = site.get("count", 1)
            if type(recorded) is not int or recorded < 1 or ("count" in site and recorded == 1):
                raise ContractError(
                    f"{where}: `count` of the site `{site['contains']}` is an integer "
                    "above one; a site that occurs once records none"
                )
            if occurrences != recorded:
                if not refresh:
                    raise ContractError(
                        f"{where}: {site['path']} contains `{site['contains']}` "
                        f"{occurrences} time(s); the contract records {recorded}"
                    )
                if occurrences == 1:
                    del site["count"]
                else:
                    site["count"] = occurrences
                if notes is not None:
                    notes.append(
                        f"{where}: site `{site['contains']}` in {site['path']} now occurs "
                        f"{occurrences} time(s), was {recorded}; confirm the change was meant"
                    )
        except ContractError as error:
            problems.append(str(error))
    for test in record.get("tests", []):
        try:
            _require(test, ("path", "name"), where)
            reason = _named_test_problem(root, test, where)
            if reason is not None:
                raise ContractError(f"{where}: test `{test['name']}` {reason} {test['path']}")
            if unreachable_test_file(root, test["path"]):
                raise ContractError(
                    f"{where}: test `{test['name']}` is in {test['path']}, which no "
                    "`mod`, `include!`, `#[path]` or test target of its crate reaches"
                )
            # A test behind a Cargo feature runs only when that feature is enabled: the
            # contract records which, so the command that runs it can be stated.
            needed = test_features(root, test, where)
            if needed is not None:
                recorded = test.get("features")
                if refresh:
                    if needed:
                        test["features"] = needed
                    else:
                        test.pop("features", None)
                    if (recorded or []) != needed and notes is not None:
                        notes.append(
                            f"{where}: test `{test['name']}` needs features {needed}, "
                            f"was {recorded or []}"
                        )
                elif (recorded or []) != needed or recorded == []:
                    raise ContractError(
                        f"{where}: test `{test['name']}` in {test['path']} is compiled "
                        f"with features {needed}; the contract records "
                        f"{recorded if recorded is not None else 'none'} in `features`"
                    )
        except ContractError as error:
            problems.append(str(error))
    for observation in record.get("observations", []):
        try:
            _require(observation, ("path", "contains", "what"), where)
            source = _normalized(_read(root, observation["path"], where))
            if normalize(observation["contains"]) not in source:
                raise ContractError(
                    f"{where}: {observation['path']} no longer contains "
                    f"`{observation['contains']}`"
                )
        except ContractError as error:
            problems.append(str(error))


def verify_bounds(root: Path, contract: dict, problems: list, refresh: bool = False) -> dict:
    """Verify every bound against its owner; return the verified id -> value map.

    With `refresh`, the recorded expression and value are replaced by what the
    source defines instead of being compared with it.
    """
    values: dict = {}
    identifiers = [bound.get("id", "<bound without id>") for bound in contract["bounds"]]
    for identifier in sorted(set(identifiers)):
        if identifiers.count(identifier) > 1:
            problems.append(f"{identifier}: duplicate bound id")
    known = set(identifiers)
    failed: set = set()
    pending = list(contract["bounds"])
    # A bound may reference a bound listed later: resolve until nothing is left.
    while pending:
        waiting = []
        for bound in pending:
            where = bound.get("id", "<bound without id>")
            refs = bound.get("refs", {})
            unresolved = [target for target in refs.values() if target not in values]
            if unresolved and all(
                target in known and target not in failed for target in unresolved
            ):
                waiting.append(bound)
                continue
            try:
                for target in unresolved:
                    raise ContractError(
                        f"{where}: `refs` names {target}, which is "
                        + ("not verified" if target in known else "not a bound")
                    )
                required = ("id", "group", "what", "unit", "source", "class", "owner")
                _require(bound, required if refresh else required + ("value",), where)
                owner = bound["owner"]
                owner_keys = ("path", "symbol", "kind")
                _require(owner, owner_keys if refresh else owner_keys + ("expr",), where)
                expression = extract_expression(
                    _read(root, owner["path"], where), owner, where
                )
                if refresh:
                    owner["expr"] = expression
                elif expression != normalize(owner["expr"]):
                    raise ContractError(
                        f"{where}: `{owner['symbol']}` in {owner['path']} is now "
                        f"`{expression}`; the contract records `{owner['expr']}`"
                    )
                value = evaluate_rust(expression, refs, values, where)
                if refresh:
                    bound["value"] = value
                elif value != bound["value"]:
                    raise ContractError(
                        f"{where}: `{owner['symbol']}` evaluates to {value}; "
                        f"the contract records {bound['value']}"
                    )
                values[where] = value
            except ContractError as error:
                problems.append(str(error))
                failed.add(where)
        if len(waiting) == len(pending):
            for bound in waiting:
                problems.append(f"{bound['id']}: `refs` form a cycle")
            break
        pending = waiting
    return values


def pin_tests(contract: dict) -> set:
    """The `(path, name)` of every test recorded as a pin of a value or projection."""
    return {(test.get("path"), test.get("name")) for test in contract.get("pin_tests", [])}


def check_pin_tests(root: Path, contract: dict, problems: list) -> None:
    """Each pin test exists, states what it pins and is named by a bound."""
    named = {
        (test.get("path"), test.get("name"))
        for bound in contract["bounds"]
        for test in bound.get("tests", [])
    }
    seen = set()
    for test in contract.get("pin_tests", []):
        where = f"pin_tests {test.get('name', '<without name>')}"
        try:
            _require(test, ("path", "name", "pins", "what"), where)
            if test["pins"] not in ("value", "projection"):
                raise ContractError(f"{where}: `pins` is `value` or `projection`")
            key = (test["path"], test["name"])
            if key in seen:
                raise ContractError(f"{where}: listed twice")
            seen.add(key)
            reason = _named_test_problem(root, test, where)
            if reason is not None:
                raise ContractError(f"{where}: {reason} {test['path']}")
            if key not in named:
                raise ContractError(f"{where}: no bound names this test")
        except ContractError as error:
            problems.append(str(error))


def check_classification(contract: dict, tasks: dict, problems: list) -> None:
    groups = set()
    pins = pin_tests(contract)
    relations = {relation.get("id"): relation for relation in contract.get("relations", [])}
    for bound in contract["bounds"]:
        where = bound.get("id", "<bound without id>")
        groups.add(bound.get("group"))
        if bound.get("group") not in GROUPS:
            problems.append(f"{where}: unknown group {bound.get('group')!r}")
        if bound.get("class") not in CLASSES:
            problems.append(f"{where}: unknown class {bound.get('class')!r}")
        if bound.get("source") not in SOURCES:
            problems.append(f"{where}: unknown source {bound.get('source')!r}")
        if bound.get("owner", {}).get("kind") not in OWNER_KINDS:
            problems.append(f"{where}: unknown owner kind")
        defect = bound.get("defect")
        if bound.get("class") == "consensus":
            if bound.get("source") == "node_local" and defect is None:
                problems.append(
                    f"{where}: a validity-affecting bound read from node-local "
                    "configuration must be recorded as a defect with an owner task"
                )
            if bound.get("source") == "committed" and not bound.get("committed_as"):
                problems.append(f"{where}: a committed bound names `committed_as`")
            if "unenforced" in bound:
                # A value that is bound into consensus state but compared nowhere yet.
                if bound.get("enforcement"):
                    problems.append(
                        f"{where}: a bound with enforcement sites is not `unenforced`"
                    )
                _check_open_owner(bound["unenforced"], tasks, f"{where}: unenforced", problems)
            elif not bound.get("enforcement"):
                problems.append(f"{where}: a consensus bound lists its enforcement sites")
            # Every consensus bound is backed by a test of its boundary, or by the task
            # that owns the gap. A test that only pins the value or shows that the value
            # changes a digest projection (`pin_tests`) is not a test of the boundary.
            tests = bound.get("tests") or []
            only_pins = bool(tests) and all(
                (test.get("path"), test.get("name")) in pins for test in tests
            )
            if "test_gap" in bound:
                if tests and not only_pins:
                    problems.append(
                        f"{where}: a bound with a test of its boundary records no `test_gap`"
                    )
                _check_open_owner(bound["test_gap"], tasks, f"{where}: test_gap", problems)
            elif not tests:
                problems.append(
                    f"{where}: a consensus bound names a test of the bound, or the task "
                    "that owns the gap in `test_gap`"
                )
            elif only_pins and "unenforced" not in bound and not bound.get("value_pin"):
                problems.append(
                    f"{where}: its tests only pin the value or a digest projection "
                    "(`pin_tests`); name a test of the boundary, the task that owns it in "
                    "`test_gap`, or state in `value_pin` why a pin is the right test"
                )
            if "value_pin" in bound and ("test_gap" in bound or not only_pins):
                problems.append(
                    f"{where}: `value_pin` is for a bound whose every test is a pin and "
                    "that records no `test_gap`"
                )
        if bound.get("class") == "local_defer":
            if bound.get("on_exhaustion") == "defer":
                if not bound.get("tests"):
                    problems.append(
                        f"{where}: a deferring local resource names the test of its deferral"
                    )
            elif bound.get("on_exhaustion") == "local_refusal":
                # A local refusal is acceptable only where a relation shows it cannot
                # refuse something the committed bounds admit (or records that gap).
                guard = relations.get(bound.get("guarded_by"))
                if guard is None:
                    problems.append(
                        f"{where}: a locally refusing bound names its relation in `guarded_by`"
                    )
            elif bound.get("on_exhaustion") == "prover_failure":
                # A limit on a proving process: nothing has been submitted yet.
                if not bound.get("note"):
                    problems.append(
                        f"{where}: a prover-side limit states in `note` why no validator "
                        "decides on it"
                    )
                if not bound.get("enforcement"):
                    problems.append(
                        f"{where}: a prover-side limit names where the prover applies it"
                    )
            else:
                problems.append(
                    f"{where}: a local resource records `on_exhaustion` as "
                    "`defer`, `local_refusal` or `prover_failure`"
                )
            if bound.get("validity") is not False:
                problems.append(f"{where}: a local resource records `validity: false`")
        if bound.get("class") == "local_schedule":
            # A time budget a node plans or waits within. Exceeding it retries or
            # re-plans one local attempt; it is neither a validity rule nor a target.
            if not bound.get("enforcement"):
                problems.append(
                    f"{where}: a local scheduling limit names where it is applied"
                )
            if bound.get("on_exceed") not in ("retry", "replan"):
                problems.append(
                    f"{where}: a local scheduling limit records `on_exceed` as "
                    "`retry` or `replan`"
                )
            if not bound.get("tests"):
                problems.append(f"{where}: a local scheduling limit names its tests")
            if bound.get("validity") is not False:
                problems.append(
                    f"{where}: a local scheduling limit records `validity: false`"
                )
        if bound.get("class") == "engineering_target":
            if bound.get("enforcement"):
                problems.append(f"{where}: an engineering target has no enforcement site")
            if bound.get("validity") is not False:
                problems.append(f"{where}: an engineering target records `validity: false`")
        if defect is not None:
            _check_open_owner(defect, tasks, f"{where}: defect", problems)
        if "inclusive" in bound and type(bound["inclusive"]) is not bool:
            problems.append(f"{where}: `inclusive` is a boolean")
    for declared in contract.get("declared", []):
        groups.add(declared.get("group"))
    for group in GROUPS:
        if group not in groups:
            problems.append(f"group `{group}` has no bound or declared item")
    stages = {
        site["stage"]
        for bound in contract["bounds"]
        for site in bound.get("enforcement", [])
        if "stage" in site
    }
    for stage in STAGES:
        if stage not in stages:
            problems.append(f"stage `{stage}` has no enforcement site")
    classes = {bound.get("class") for bound in contract["bounds"]}
    for name in CLASSES:
        if name not in contract.get("classes", {}):
            problems.append(f"class `{name}` is not described in `classes`")
        if name not in classes:
            problems.append(f"class `{name}` has no bound")


def _check_open_owner(record: dict, tasks: dict, where: str, problems: list) -> None:
    owner = record.get("owner")
    if owner not in tasks:
        problems.append(f"{where}: owner `{owner}` is not a task of the delivery graph")
    elif tasks[owner] == "implemented":
        problems.append(
            f"{where}: task {owner} is recorded implemented; reconcile this open item"
        )
    if not record.get("summary"):
        problems.append(f"{where}: an open item states what is open in `summary`")


def check_fixed(contract: dict, values: dict, problems: list) -> None:
    by_id = {bound.get("id"): bound for bound in contract["bounds"]}
    for identifier, expected in FIXED_BOUNDS.items():
        bound = by_id.get(identifier)
        if bound is None:
            problems.append(f"{identifier}: the fixed bound is missing from the contract")
            continue
        if bound.get("fixed") is not True:
            problems.append(f"{identifier}: the bound is recorded `fixed: true`")
        if bound.get("value") != expected or values.get(identifier, expected) != expected:
            problems.append(
                f"{identifier}: the delivery plan fixes {expected}; "
                f"the contract records {bound.get('value')}"
            )
    for identifier in FRAMED_BOUNDS:
        if not by_id.get(identifier, {}).get("framing"):
            problems.append(
                f"{identifier}: states in `framing` which encoding overhead the length includes"
            )
    pins = pin_tests(contract)
    for identifier in FIXED_VALIDITY:
        bound = by_id.get(identifier, {})
        if (
            bound.get("class") != "consensus"
            or not bound.get("enforcement")
            or not bound.get("tests")
        ):
            problems.append(
                f"{identifier}: a fixed validity bound is classed consensus with its "
                "enforcement sites and tests"
            )
        elif all((test.get("path"), test.get("name")) in pins for test in bound["tests"]):
            problems.append(
                f"{identifier}: a fixed validity bound names a test of its boundary, "
                "not only a pin of its value"
            )
    for identifier in FIXED_NON_VALIDITY:
        bound = by_id.get(identifier, {})
        if bound.get("class") == "consensus":
            problems.append(
                f"{identifier}: a prover time or memory bound is never consensus validity"
            )


def _block_end(source: str, open_index: int) -> int:
    """Index just past the block whose `{` is at `open_index`, or -1 when it is not closed.

    String literals and line comments are skipped, so a brace inside them does not count.
    """
    depth = 0
    index = open_index
    length = len(source)
    while index < length:
        char = source[index]
        if char == '"':
            index += 1
            while index < length and source[index] != '"':
                index += 2 if source[index] == "\\" else 1
        elif char == "/" and source.startswith("//", index):
            newline = source.find("\n", index)
            index = length if newline < 0 else newline
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    return -1


def _module_block(source: str, anchors: list, where: str) -> str:
    """Return the brace-delimited block of a nested module path (each anchor ends with `{`)."""
    for anchor in anchors[:-1]:
        position = source.find(anchor)
        if position < 0:
            raise ContractError(f"{where}: module `{anchor}` is not in the file")
        source = source[position + len(anchor) :]
    anchor = anchors[-1]
    start = source.find(anchor)
    if start < 0:
        raise ContractError(f"{where}: module `{anchor}` is not in the file")
    end = _block_end(source, start + len(anchor) - 1)
    if end < 0:
        raise ContractError(f"{where}: module `{anchor}` is not closed")
    return source[start:end]


def inline_test_modules(source: str) -> tuple:
    """`(start, open)` of every inline module that only a test build compiles.

    `open` is the `{` of `mod name {` and `start` is where the attributes in front of it
    begin. The module is a test module when one of its `cfg` gates holds only in a test
    build, in any order and nesting the attribute is written in: `#[cfg(test)]`,
    `#[cfg(all(test, feature = ".."))]`, `#[cfg(all(feature = "..", test))]`, an
    attribute that spans lines. Other attributes and doc comments may stand between.
    """
    return _TEXTS.get(source, "inline_test_modules", lambda: _inline_test_modules(source))


def _inline_test_modules(source: str) -> tuple:
    found = []
    for match in INLINE_MODULE.finditer(source):
        # The attributes of the item: the text after the previous item or block ends,
        # with its line comments blanked in place so offsets stay those of the source.
        low = max(0, match.start() - 2000)
        window = LINE_COMMENT.sub(lambda comment: " " * len(comment.group(0)), source[low : match.start()])
        head = max(window.rfind(";"), window.rfind("}"), window.rfind("{")) + 1
        if cfg_requires_test(window[head:]):
            start = low + head
            while start < match.start() and source[start] in " \t\n":
                start += 1
            found.append((start, match.end() - 1))
    return tuple(found)


def _without_inline_tests(source: str) -> str:
    """Remove every inline test module (`inline_test_modules`; computed once per text)."""
    return _TEXTS.derive(source, "without_inline_tests", lambda: _strip_inline_tests(source))


def _strip_inline_tests(source: str) -> str:
    kept = []
    position = 0
    # The block of a module is read on the code mask: a brace or a quote inside a
    # character literal, a raw string or a block comment of the tests does not move its end.
    mask = source_mask(source)
    for start, opening in inline_test_modules(source):
        if start < position:
            continue
        end = _mask_block_end(mask, opening)
        kept.append(source[position:start])
        position = len(source) if end < 0 else end
    kept.append(source[position:])
    return "".join(kept)


# ---------------------------------------------------------------------------
# Limits that their name does not mark
# ---------------------------------------------------------------------------
#
# A scope with `comparisons` is read a second way, by what the code compares:
#
# * an integer constant (or immutable integer `static`) of any name that takes part in a
#   relational comparison (`<`, `<=`, `>`, `>=`, also written `.lt(..)`, `.le(..)`,
#   `.gt(..)`, `.ge(..)`), in a capping call (`.min(..)`, `.max(..)`, `.clamp(..)`,
#   `.take(..)`, `.truncate(..)`), in either called as a function behind any path, or in
#   a range tested with `.contains(..)` is a limit like one named MAX, and so is an
#   integer constant that the defining expression of a scanned limit names (a term of
#   it). A call compares its arguments and, for `.min`, `.max`, `.clamp` and the
#   comparison methods, its receiver: the whole method chain in front of the call
#   (`_receiver_start`). A tested range compares its ends and the value it tests;
# * a function without parameters whose name marks a limit (`max_..`, `.._limit`,
#   `.._budget`, `.._cap`, ..) and that returns an integer, an `Option` of one or a
#   `Result` of one is a limit written as a function;
# * an integer literal of `minimum` or more that is compared, capped with or the end of a
#   tested range is a limit without a name: a literal site. So is one that is only a part
#   of what is compared (`MAX + 1024`, `len / 2 >= MAX`, `Duration::from_secs(30)`, a
#   factor in a capped receiver chain): its site is the whole comparison, capping call
#   or tested range. Constants and literals are read from the same text.
#
# The reading is textual, on rustfmt-formatted code (a comparison operator has whitespace
# on both sides; a generic bracket has none).

INTEGER_TYPE = r"(?:[ui](?:8|16|32|64|128|size)|(?:(?:core|std)::num::)?NonZero[A-Za-z0-9]+)"
# An integer `const` or `static` item: the type is followed by `=` (its value) or `;` (a
# trait constant). A const generic parameter (`const N: usize,`) is not an item.
INTEGER_ITEM = re.compile(
    r"(?:^|[{;])[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?(?:const|static)[ \t]+([A-Z][A-Z0-9_]*)[ \t]*:"
    r"[ \t]*" + INTEGER_TYPE + r"\b[ \t]*(?=[=;\n])(?!\n[ \t]*[,>])",
    re.MULTILINE,
)
# Names that mark a function as a limit, the lower-case form of `LIMIT_NAME`.
LIMIT_FN_NAME = re.compile(
    r"(?:^|_)(?:max|maximum)(?:_|$)|limit|budget|ceiling|overhead|reserve"
    r"|(?:^|_)cap(?:acity)?(?:_|$)"
)
# The return type of a limit written as a function: an integer, or one inside `Option`
# or as the value of a `Result` (a limit that may be absent or may fail to be read).
LIMIT_FN_RETURN = (
    r"(?:" + INTEGER_TYPE + r"|Option<\s*" + INTEGER_TYPE + r"\s*>"
    r"|(?:[A-Za-z_][A-Za-z_0-9]*::)*Result<\s*" + INTEGER_TYPE + r"\s*(?:,[^{;]*)?>)"
)
LIMIT_FN_DEFINITION = re.compile(
    r"\bfn[ \t]+([a-z_][a-z0-9_]*)[ \t]*\(\s*\)\s*->\s*" + LIMIT_FN_RETURN + r"\s*\{"
)
_INTEGER = (
    r"(?:0x[0-9a-fA-F_]+|0b[01_]+|0o[0-7_]+|[0-9][0-9_]*)"
    r"(?:_?[ui](?:8|16|32|64|128|size))?"
)
_INTEGER_TERM = re.compile(_INTEGER)
# A literal bound: integer literals joined by `*` or `<<` (`4 * 1024 * 1024`, `1 << 20`).
LITERAL_EXPRESSION = re.compile(rf"{_INTEGER}(?:\s*(?:\*|<<)\s*{_INTEGER})*")
RELATIONAL = re.compile(r"(?<=\s)(?:<=|>=|<|>)(?=\s)")
# A cap written as a method (`a.min(b)`, `a.clamp(low, high)`, `items.take(n)`,
# `buffer.truncate(n)`) and a comparison written as one (`a.lt(&b)`, `.le`, `.gt`, `.ge`).
CAP_CALL = re.compile(r"\.\s*(min|max|clamp|take|truncate|lt|le|gt|ge)\s*\(")
# The calls that compare their receiver with their arguments. `.take(n)` and
# `.truncate(n)` bound a collection: only `n` is compared there.
COMPARED_RECEIVER = frozenset(("min", "max", "clamp", "lt", "le", "gt", "ge"))
# The same cap or comparison written as a function, bare or behind any path:
# `min(a, b)`, `cmp::min(a, b)`, `u64::max(a, b)`, `core::cmp::Ord::max(a, b)`,
# `NonZeroU32::min(a, b)`, `<u64 as Ord>::max(a, b)`, `u32::clamp(n, 2, 64)`,
# `PartialOrd::lt(&a, &b)`. The definition of such a function (`fn max(..)`) is none.
CAP_FUNCTION = re.compile(
    r"(?<![A-Za-z0-9_.:>])(?<!\bfn )(?:(?:[A-Za-z_][A-Za-z_0-9]*|<[^<>()]*>)::)*"
    r"(?:min|max|clamp|lt|le|gt|ge)\s*\("
)
RANGE_TEST = re.compile(r"\)\s*\.\s*contains\s*\(")
# One integer literal inside a larger expression: no part of a name, of a float
# (`0.5`, `1e9`, `2f64`) or of a tuple field (`pair.0`); a range end (`..31`) is one.
_PART_LITERAL = re.compile(rf"(?<![A-Za-z0-9_])(?<![^.]\.){_INTEGER}(?![A-Za-z0-9_]|\.[0-9])")
# What may stand in front of a compared clause without being part of it: a keyword or
# the head of a closure (`|x|`).
_CLAUSE_HEAD = re.compile(r"(?:(?:else\s+)?if|while|return|match|move)\b\s*|\|[^|\n]*\|\s*")
# A name written in upper case: a constant (also one of a single letter; a generic
# parameter of that form names no integer item and is dropped when names are attributed).
_CONSTANT_NAME = re.compile(r"(?<![A-Za-z0-9_])([A-Z][A-Z0-9_]*)\b(?![ \t]*(?:::|\(|!|\{))")
_CLAUSE_WINDOW = 600
# How many constants deep a chain of terms is followed (`_compared`); a longer one fails.
_TERM_ROUNDS = 16


def literal_value(text: str) -> int | None:
    """The value of a literal bound (`LITERAL_EXPRESSION`), or None when it is not one."""
    if not LITERAL_EXPRESSION.fullmatch(text.strip()):
        return None

    def number(match: re.Match) -> str:
        digits = re.sub(r"_?[ui](?:8|16|32|64|128|size)$", "", match.group(0)).replace("_", "")
        prefix = digits[:2].lower()
        base = {"0x": 16, "0b": 2, "0o": 8}.get(prefix, 10)
        return str(int(digits[2:] if base != 10 else digits, base))

    try:
        value = safe_eval(_INTEGER_TERM.sub(number, text.strip()), "literal")
    except (ContractError, ValueError, OverflowError):
        return None
    return value if type(value) is int else None


def _mask_block_end(mask: str, open_index: int) -> int:
    """Index just past the block whose `{` is at `open_index` in a code mask, or -1."""
    depth = 0
    for match in _BRACE.finditer(mask, open_index):
        depth += 1 if match.group(0) == "{" else -1
        if depth == 0:
            return match.end()
    return -1


def production_mask(source: str) -> str:
    """The code mask of `source` with every inline test module blanked as well.

    Offsets are those of `source`. What remains is the code a non-test build compiles.
    """
    mask = source_mask(source)
    pieces = []
    position = 0
    for start, opening in inline_test_modules(source):
        if start < position:
            continue
        end = _mask_block_end(mask, opening)
        end = len(mask) if end < 0 else end
        pieces.append(mask[position:start])
        pieces.append(_NOT_NEWLINE.sub(" ", mask[start:end]))
        position = end
    pieces.append(mask[position:])
    return "".join(pieces)


def _clause_start(mask: str, index: int) -> int:
    """Start of the clause that ends at `index`: after the previous `;`, `,`, brace, `&&`,
    `||`, assignment or the bracket that is still open."""
    depth = 0
    floor = max(0, index - _CLAUSE_WINDOW)
    position = index
    while position > floor:
        char = mask[position - 1]
        if char in ")]":
            depth += 1
        elif char in "([":
            if depth == 0:
                break
            depth -= 1
        elif depth == 0:
            if char in ";{},":
                break
            pair = mask[position - 2 : position]
            if pair in ("&&", "||"):
                break
            if char == "=" and mask[position - 2 : position - 1] not in ("=", "!", "<", ">") and (
                mask[position : position + 1] != "="
            ):
                break
        position -= 1
    return position


def _clause_end(mask: str, index: int) -> int:
    """End of the clause that starts at `index`: before the next `;`, `,`, brace, `&&`,
    `||`, `=>` or the bracket that closes an enclosing group."""
    depth = 0
    ceiling = min(len(mask), index + _CLAUSE_WINDOW)
    position = index
    while position < ceiling:
        char = mask[position]
        if char in "([":
            depth += 1
        elif char in ")]":
            if depth == 0:
                break
            depth -= 1
        elif depth == 0:
            if char in ";{},":
                break
            if mask[position : position + 2] in ("&&", "||", "=>"):
                break
        position += 1
    return position


def _operand_start(mask: str, end: int, hops: int = 6) -> int:
    """Start of the operand that ends at `end`.

    An operand is one run without whitespace outside brackets (`self.items.len()`,
    `u64::from(count)`); a method chain broken across lines and an `as` cast in front of
    the operator are followed back, at most `hops` runs.
    """
    index = end
    for hop in range(hops):
        while index > 0 and mask[index - 1] in " \t\n":
            index -= 1
        stop = index
        depth = 0
        while index > 0:
            char = mask[index - 1]
            if char in ")]":
                depth += 1
            elif char in "([":
                if depth == 0:
                    break
                depth -= 1
            elif depth == 0 and char in " \t\n,;{}":
                break
            index -= 1
        chunk = mask[index:stop]
        if not chunk:
            return stop
        before = index
        while before > 0 and mask[before - 1] in " \t\n":
            before -= 1
        cast = mask[max(0, before - 3) : before] == " as" or mask[max(0, before - 3) : before] == "\nas"
        if chunk[0] in ".?":
            continue
        if cast:
            index = before - 2
            continue
        # Arithmetic in front of the run belongs to the operand: `offset + 1 < 32`.
        if (
            hop + 1 < hops
            and before < index
            and mask[before - 1 : before] in ("+", "-", "*", "/", "%")
            and mask[before - 2 : before - 1] in (" ", "\t", "\n")
        ):
            index = before - 1
            continue
        return index
    return index


def _run_start(mask: str, end: int) -> tuple:
    """`(start, stop)` of the run without whitespace outside brackets in front of `end`.

    `stop` is `end` without the blanks in front of it; the run is empty (`start == stop`)
    when a separator, a brace or an opening bracket stands there.
    """
    stop = end
    while stop > 0 and mask[stop - 1] in " \t\n":
        stop -= 1
    index = stop
    depth = 0
    while index > 0:
        char = mask[index - 1]
        if char in ")]":
            depth += 1
        elif char in "([":
            if depth == 0:
                break
            depth -= 1
        elif depth == 0 and char in " \t\n,;{}":
            break
        index -= 1
    return index, stop


def _receiver_start(mask: str, end: int) -> int:
    """Start of the receiver of the method call whose `.` is at `end`.

    The receiver is the whole method chain in front of the call, however many lines
    rustfmt breaks it into: every element that starts with `.` or `?` on a line of its
    own is followed back, up to the head of the chain (a name, a path, a call, a
    literal, a parenthesised expression). Arithmetic in front of the head is no part of
    the receiver: in `a + b.min(c)` it is `b`. A head that the mask blanked (a string or
    character literal: `"ab".len().min(4)`) ends the chain where it stood, and so does a
    block (`match kind { .. }.min(cap)`): what a block yields is not read.
    """
    index = end
    while True:
        start, stop = _run_start(mask, index)
        if start == stop:
            return index
        index = start
        if mask[start] not in ".?" or "\n" not in mask[_run_start(mask, start)[1] : start]:
            return start


def _operand_end(mask: str, start: int, hops: int = 6) -> int:
    """End of the operand that starts at `start` (the mirror of `_operand_start`)."""
    index = start
    length = len(mask)
    for _ in range(hops):
        while index < length and mask[index] in " \t\n":
            index += 1
        depth = 0
        while index < length:
            char = mask[index]
            if char in "([":
                depth += 1
            elif char in ")]":
                if depth == 0:
                    break
                depth -= 1
            elif depth == 0 and char in " \t\n,;{}":
                break
            index += 1
        ahead = index
        while ahead < length and mask[ahead] in " \t\n":
            ahead += 1
        if mask[ahead : ahead + 1] == "." and mask[ahead : ahead + 2] != "..":
            index = ahead
            continue
        return index
    return index


def _compared_clause(mask: str, start: int, end: int) -> tuple:
    """`(left, right)` of the comparison whose operator is `mask[start:end]`, both operands whole.

    The clause of `_clause_start` and `_clause_end` without the blanks around it and
    without what stands in front of a comparison and is no part of it: the `=>` of a
    match arm, a keyword (`if`, `while`, `return`, `match`, `move`) and the head of a
    closure (`|x|`). An operand longer than the clause window is cut at a blank, so no
    name or literal is read in part. `left == start` when nothing is compared (the `>`
    that closes a generic list on a line of its own).
    """
    left = _clause_start(mask, start)
    right = _clause_end(mask, end)
    if start - left >= _CLAUSE_WINDOW:
        while left < start and mask[left] not in " \t\n":
            left += 1
    if right - end >= _CLAUSE_WINDOW:
        while right > end and mask[right - 1] not in " \t\n":
            right -= 1
    if mask[left : left + 1] == ">" and mask[left - 1 : left] == "=":
        left += 1
    while True:
        while left < start and mask[left] in " \t\n":
            left += 1
        head = _CLAUSE_HEAD.match(mask, left, start)
        if head is None or head.end() == left:
            break
        left = head.end()
    while right > end and mask[right - 1] in " \t\n":
        right -= 1
    return left, right


def _literal_after(mask: str, index: int) -> tuple | None:
    """`(start, end)` of a literal bound that is the whole operand after `index`."""
    start = index
    while start < len(mask) and mask[start] in " \t\n":
        start += 1
    match = LITERAL_EXPRESSION.match(mask, start)
    if match is None:
        return None
    # What follows the literal is read past every blank: the expression may go on in the
    # next line at any depth of indentation, and the literal may end the text.
    ahead = match.end()
    while ahead < len(mask) and mask[ahead] in " \t\n":
        ahead += 1
    first, pair = mask[ahead : ahead + 1], mask[ahead : ahead + 2]
    # The literal is the operand only when nothing continues the expression.
    if first and (first in "*/+-%.^([<>" or first.isalnum() or first == "_"):
        return None
    if first and first in "&|" and pair not in ("&&", "||"):
        return None
    return match.start(), match.end()


def _literal_before(mask: str, index: int) -> tuple | None:
    """`(start, end)` of a literal bound that is the whole operand before `index`."""
    end = index
    while end > 0 and mask[end - 1] in " \t\n":
        end -= 1
    window = mask[max(0, end - 96) : end]
    match = re.search(rf"(?:{LITERAL_EXPRESSION.pattern})$", window)
    if match is None:
        return None
    start = end - len(window) + match.start()
    # The literal is the operand only when nothing in front of it continues an expression:
    # it follows an opening bracket, a separator, an assignment or a keyword.
    # Read back past every blank, for the same reason as in `_literal_after`.
    behind = start
    while behind > 0 and mask[behind - 1] in " \t\n":
        behind -= 1
    before = mask[max(0, behind - 24) : behind]
    if before[-1:] and before[-1:] not in "([{,;=&|!:":
        if re.search(r"(?:\bif|\bwhile|\breturn|\bin|\belse|\bmatch|=>)$", before) is None:
            return None
    return start, end


def _top_level_parts(text: str) -> list:
    """`(start, end)` of every comma-separated part of `text` outside brackets."""
    parts = []
    depth = 0
    start = 0
    for index, char in enumerate(text):
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == "," and depth == 0:
            parts.append((start, index))
            start = index + 1
    parts.append((start, len(text)))
    return parts


def comparison_scan(source: str) -> dict:
    """What the production code of one source compares, read once per text.

    * `uses`: names of constants that take part in a relational comparison, in the
      arguments or the compared receiver of a capping or comparison call, or in a
      tested range and the value it tests;
    * `integers`: the integer constants and immutable integer statics the text defines;
    * `items`: every constant and static the text defines, of any type;
    * `functions`: limit-named functions without parameters that return an integer, with
      the span of each body;
    * `sites`: literal sites whose literal is a whole operand, argument or range end, as
      `(text_start, text_end, literal_start, literal_end, value)`;
    * `regions`: every compared clause, capping call and tested range that holds an
      integer literal of 2 or more, as `(text_start, text_end, wide_start, literals)` with
      `literals` as `(start, end, value)`; `wide_start`, when it lies before `text_start`,
      is where a compared receiver begins that is longer than the text of a site: the
      head of its method chain.
    """
    return _TEXTS.get(source, "comparison_scan", lambda: _comparison_scan(source))


def _comparison_scan(source: str) -> dict:
    """`comparison_scan` of one text, read from its production mask."""
    mask = production_mask(source)
    uses: set = set()
    sites: list = []
    for match in RELATIONAL.finditer(mask):
        left = _clause_start(mask, match.start())
        right = _clause_end(mask, match.end())
        uses.update(_CONSTANT_NAME.findall(mask[left:right]))
        after = _literal_after(mask, match.end())
        before = _literal_before(mask, match.start())
        if (after is None) == (before is None):
            # No literal operand, or a comparison of two literals: nothing is bounded.
            continue
        if after is not None:
            value = literal_value(mask[after[0] : after[1]])
            start = _operand_start(mask, match.start())
            if value is not None and start < match.start():
                sites.append((start, after[1], after[0], after[1], value))
        else:
            value = literal_value(mask[before[0] : before[1]])
            end = _operand_end(mask, match.end())
            if value is not None and end > match.end():
                sites.append((before[0], end, before[0], before[1], value))
    # Capping calls, as a method and as a function. `regions` keeps, for the part
    # literals read below, the text each one compares: `(start, end, search, wide)`.
    # Literals are looked for from `search`; `wide`, when it lies before `start`, is
    # where a receiver too long for the text of the site begins.
    regions: list = []
    for pattern in (CAP_CALL, CAP_FUNCTION):
        for match in pattern.finditer(mask):
            close = _group_end(mask, match.end() - 1, "(", ")")
            if close < 0:
                continue
            arguments = mask[match.end() : close - 1]
            uses.update(_CONSTANT_NAME.findall(arguments))
            receiver = search = wide = match.start()
            if pattern is CAP_CALL:
                whole = _run_start(mask, match.start())[0]
                literal_receiver = literal_value(mask[whole : match.start()]) is not None
                if match.start() - whole <= 48 or literal_receiver:
                    receiver = whole
                # Otherwise a long receiver (a chain element with a closure) is no part
                # of the site: the text starts at the call.
                if match.group(1) in COMPARED_RECEIVER or literal_receiver:
                    # `a.min(b)` compares both values, so a constant or a literal in `a`
                    # is compared too. `a` is the whole method chain in front of the
                    # call, on one line or on several.
                    search, wide = receiver, _receiver_start(mask, match.start())
                    uses.update(_CONSTANT_NAME.findall(mask[wide : match.start()]))
                else:
                    search = match.end()
            regions.append((receiver, close, search, wide))
            for start, end in _top_level_parts(arguments):
                part = arguments[start:end]
                value = literal_value(part)
                if value is not None:
                    lead = len(part) - len(part.lstrip())
                    literal = match.end() + start + lead
                    sites.append((receiver, close, literal, literal + len(part.strip()), value))
    for match in RANGE_TEST.finditer(mask):
        # The range in the parentheses that close at the match: `(1..=31).contains(&x)`.
        depth = 0
        opening = match.start()
        while opening >= 0:
            if mask[opening] == ")":
                depth += 1
            elif mask[opening] == "(":
                depth -= 1
                if depth == 0:
                    break
            opening -= 1
        close = _group_end(mask, match.end() - 1, "(", ")")
        if opening < 0 or close < 0:
            continue
        inside = mask[opening + 1 : match.start()]
        dots = inside.find("..")
        if dots < 0 or match.start() - opening > _CLAUSE_WINDOW:
            continue
        # The range and the value it tests: `(MIN..=MAX).contains(&WIDTH)`.
        uses.update(_CONSTANT_NAME.findall(mask[opening:close]))
        regions.append((opening, close, opening, opening))
        upper = inside[dots + 2 :].lstrip("=")
        value = literal_value(upper)
        if value is not None:
            lead = len(upper) - len(upper.lstrip())
            literal = match.start() - len(upper) + lead
            sites.append((opening, close, literal, literal + len(upper.strip()), value))
    # Part literals. A literal that is only a part of what is compared (`MAX + 1024`,
    # `2 * MAX`, `len / 2 >= MAX`, `height.saturating_add(1_000_000)`,
    # `Duration::from_secs(30)`, `(1 << 12)`) moves the limit like one that is the whole
    # operand. Every compared clause, capping call and tested range is kept with the
    # integer literals it holds; `literal_sites` makes a site of those that the text of
    # no other site holds. Capping calls and ranges come first, so a comparison around
    # one records only the literals that are left.
    for match in RELATIONAL.finditer(mask):
        left, right = _compared_clause(mask, match.start(), match.end())
        if left < match.start():
            regions.append((left, right, left, left))
    compared = []
    for start, end, search, wide in regions:
        literals = tuple(
            (literal.start(), literal.end(), value)
            for literal in _PART_LITERAL.finditer(mask, min(search, wide), end)
            if (literal.start() >= search or literal.start() < start)
            and (value := literal_value(literal.group(0))) is not None
            and value >= 2
        )
        if literals:
            compared.append((start, end, wide, literals))
    functions: dict = {}
    for match in LIMIT_FN_DEFINITION.finditer(mask):
        if LIMIT_FN_NAME.search(match.group(1)):
            end = _mask_block_end(mask, match.end() - 1)
            functions.setdefault(match.group(1), []).append(
                (match.end(), (len(mask) if end < 0 else end) - 1)
            )
    return {
        "uses": frozenset(uses),
        "integers": tuple(dict.fromkeys(match.group(1) for match in INTEGER_ITEM.finditer(mask))),
        "items": frozenset(match.group(1) for match in _ITEM_DEFINITION.finditer(mask)),
        "functions": functions,
        "sites": tuple(sorted(set(sites))),
        "regions": tuple(compared),
    }


def literal_sites(source: str, minimum: int) -> dict:
    """Literal sites of one source: normalized text -> the literal spans that show it.

    Only literals of `minimum` or more count. A site whose literal is a whole operand
    has as its text the operand, the operator and the literal as the source writes them
    (`value.len() > 128`), so the same text is what an enforcement site of a bound
    contains when the bound owns the comparison. A literal that is only a part of what
    is compared (`value.len() > MAX + 1024`) is a site whose text is the whole
    comparison, capping call or tested range, unless the text of another site holds it
    already. Each span is `(literal_start, literal_end, value)`: every literal the text
    of the site holds, so one text has several spans when it occurs more than once or
    holds more than one literal.
    """
    return _literal_sites(source, minimum)[0]


def literal_occurrences(source: str, minimum: int) -> dict:
    """Literal sites of one source: normalized text -> how many times the text occurs as a site.

    A comparison that holds two literals (`.clamp(2, 64)`, `len < 37 + 16`) is one
    occurrence of its text.
    """
    return _literal_sites(source, minimum)[1]


def _literal_sites(source: str, minimum: int) -> tuple:
    """`(literal_sites, literal_occurrences)` of one source, read once per text and minimum."""

    def read() -> tuple:
        scan = comparison_scan(source)
        found: dict = {}
        for start, end, literal_start, literal_end, value in scan["sites"]:
            if value >= minimum:
                found.setdefault((start, end), []).append((literal_start, literal_end, value))
        # Texts that hold a literal, shortest first: a literal belongs to the innermost.
        held = sorted(found, key=lambda span: (span[1] - span[0], span))
        for start, end, wide, literals in scan["regions"]:
            loose = []
            for literal in literals:
                if literal[2] < minimum:
                    continue
                holder = next(
                    (span for span in held if span[0] <= literal[0] < span[1]), None
                )
                if holder is None:
                    loose.append(literal)
                elif not any(low <= literal[0] < high for low, high, _ in found[holder]):
                    # The text of that site pins this literal too: the sweep changes it.
                    found[holder].append(literal)
            if loose:
                if any(low < start for low, _, _ in loose):
                    # A literal in a compared receiver too long for the usual text.
                    start = wide
                # From here on the text of this site holds its literals: a site around
                # it adds none of them again.
                found.setdefault((start, end), []).extend(loose)
                held = sorted(found, key=lambda span: (span[1] - span[0], span))
        spans: dict = {}
        occurrences: dict = {}
        for (start, end), literals in sorted(found.items()):
            text = normalize(source[start:end])
            spans.setdefault(text, []).extend(sorted(set(literals)))
            occurrences[text] = occurrences.get(text, 0) + 1
        return spans, occurrences

    return _TEXTS.get(source, ("literal_sites", minimum), read)


def function_body_spans(source: str, symbol: str) -> list:
    """`(start, end)` of the body of every `fn symbol() -> .. { .. }` in `source`."""
    spans = []
    for match in re.finditer(rf"\bfn\s+{re.escape(symbol)}\s*\(\s*\)\s*->\s*[^{{;]+\{{", source):
        end = _block_end(source, match.end() - 1)
        if end > 0:
            spans.append((match.end(), end - 1))
    return spans


def _crate_prefix(path: str) -> str:
    """`crates/<name>` of a repository path (the path itself when it has no such prefix)."""
    parts = path.split("/")
    return "/".join(parts[:2]) if len(parts) > 2 else path


_REFERENCED_NAME = re.compile(
    r"(?<![A-Za-z0-9_])((?:[A-Za-z_][A-Za-z_0-9]*::)*)([A-Z][A-Z0-9_]*)\b(?![ \t]*(?:::|\(|!|\{))"
)


_PRIMITIVE_TYPE = re.compile(r"(?:[ui](?:8|16|32|64|128|size)|f32|f64|char|bool|str)")


def referenced_constants(expression: str) -> set:
    """Names of the constants an expression refers to by a bare name or a module path.

    An associated constant of a type (`Header::SIZE`, `u64::MAX`, `u32::BITS`) is not
    resolved by its name and is left out; `Self::NAME` is a constant of the same file
    and counts.
    """
    names = set()
    # A name inside a string literal or a comment of the expression is text, not a constant.
    for match in _REFERENCED_NAME.finditer(code_mask(expression)):
        qualifier = match.group(1)[:-2].rsplit("::", 1)[-1]
        if (qualifier[:1].isupper() and qualifier != "Self") or _PRIMITIVE_TYPE.fullmatch(qualifier):
            continue
        names.add(match.group(2))
    return names


def _attributed(scans: dict, mentions: dict) -> dict:
    """Path -> the integer constants of that file that `mentions` (path -> names) refer to.

    A name refers to the constant of its own file; from a file that defines no item of
    that name, to the constants of that name in the scanned files of its crate; and from
    a crate that defines no integer constant of the name, to those of the other crates
    (an import).
    """
    external: dict = {}
    defined: dict = {}
    for path, scan in scans.items():
        crate = _crate_prefix(path)
        external.setdefault(crate, set()).update(mentions.get(path, set()) - scan["items"])
        defined.setdefault(crate, set()).update(scan["integers"])
    imported: set = set()
    for crate, names in external.items():
        imported |= names - defined.get(crate, set())
    return {
        path: [
            name
            for name in scan["integers"]
            if name in mentions.get(path, ())
            or name in external.get(_crate_prefix(path), ())
            or name in imported
        ]
        for path, scan in scans.items()
    }


def _refers_to(scans: dict, defined: dict, user: str, name: str, target: str) -> bool:
    """Whether `name` written in file `user` is the integer constant `name` of file `target`.

    The rule of `_attributed`, for one name and one pair of files.
    """
    if user == target:
        return True
    if name in scans[user]["items"]:
        return False
    if _crate_prefix(user) == _crate_prefix(target):
        return True
    return name not in defined.get(_crate_prefix(user), ())


def compared_symbols(root: Path, scopes: list) -> dict:
    """Path -> the limits of each `comparisons` scope that their name does not mark.

    In source order: the integer constants whose name takes part in a comparison
    (`_attributed`), then the limit-named functions without parameters, then the terms:
    integer constants that the defining expression of a scanned limit of these scopes
    names (`referenced_constants`), followed until no new one appears. A term is part of
    the value of the limit that names it.
    """
    return _compared(root, scopes)[0]


def limit_terms(root: Path, scopes: list) -> dict:
    """Path -> each term of that file with the limits that name it.

    A term is an integer constant that is a limit neither by its name nor by a
    comparison of its own: it is scanned only because the defining expression of a
    scanned limit names it. The value is the sorted list of those limits, each written
    `path: SYMBOL`. An exclusion of a term records this list as `term_of`.
    """
    return _compared(root, scopes)[1]


def _compared(root: Path, scopes: list) -> tuple:
    """`(compared_symbols, limit_terms)` of the `comparisons` scopes, read in one pass."""
    scans: dict = {}
    whole: dict = {}
    # Each source is read once for the whole pass.
    sources: dict = {}
    for scope in scopes:
        if scope.get("comparisons") and scope.get("kind") == "const" and not scope.get("module"):
            path = scope["path"]
            if path not in scans:
                try:
                    sources[path] = _read(root, path, f"completeness {path}")
                except ContractError:
                    continue
                scans[path] = comparison_scan(sources[path])
                whole[path] = scope
    used = _attributed(scans, {path: scan["uses"] for path, scan in scans.items()})
    found: dict = {}
    for path, scan in scans.items():
        names = [name for name in used[path] if not LIMIT_NAME.search(name)]
        names.extend(scan["functions"])
        found[path] = names
    # Terms: read the expression of every scanned limit once, and of every term it adds.
    pending = {}
    for path in scans:
        pending[path] = (
            scope_symbols(sources[path], whole[path], f"completeness {path}") + found[path]
        )
    mentions: dict = {path: set() for path in scans}
    named_by: dict = {}
    terms_of: dict = {}
    for _ in range(_TERM_ROUNDS):
        for path, symbols in pending.items():
            where = f"completeness {path}"
            source = sources[path]
            for symbol in symbols:
                for name in referenced_constants(
                    scope_expression(source, whole[path], symbol, where)
                ):
                    mentions[path].add(name)
                    named_by.setdefault(name, set()).add((path, symbol))
        pending = {}
        for path, names in _attributed(scans, mentions).items():
            known = set(found[path])
            terms = [
                name for name in names if name not in known and not LIMIT_NAME.search(name)
            ]
            if terms:
                found[path].extend(terms)
                terms_of.setdefault(path, {}).update(dict.fromkeys(terms))
                pending[path] = terms
        if not pending:
            break
    else:
        raise ContractError(
            f"completeness: a chain of terms is longer than {_TERM_ROUNDS} constants; "
            "raise `_TERM_ROUNDS`"
        )
    defined: dict = {}
    for path, scan in scans.items():
        defined.setdefault(_crate_prefix(path), set()).update(scan["integers"])
    for path, terms in terms_of.items():
        for term in terms:
            terms[term] = sorted(
                f"{user}: {symbol}"
                for user, symbol in named_by.get(term, ())
                if (user, symbol) != (path, term) and _refers_to(scans, defined, user, term, path)
            )
    return found, terms_of


def scanned_symbols(source: str, scope: dict, where: str, compared: dict | None = None) -> list:
    """Every limit of one scope: those its name marks, then those the code compares."""
    symbols = scope_symbols(source, scope, where)
    for name in (compared or {}).get(scope.get("path"), ()) if scope.get("comparisons") else ():
        if name not in symbols:
            symbols.append(name)
    return symbols


def _is_function_symbol(scope: dict, symbol: str) -> bool:
    """Whether a scanned symbol is a function: a default of a module, or a lower-case name."""
    return scope.get("kind") == "default_fn" or not symbol[:1].isupper()


def scope_symbols(source: str, scope: dict, where: str) -> list:
    """Return the limit symbols a completeness scope defines, in source order.

    A `const` scope finds every constant whose name marks a limit (`LIMIT_NAME`, or the
    scope's own `matching` pattern, which must come with a `why`). A `default_fn` scope
    finds every zero-argument default of a committed-parameter module. Inline test
    modules are not scanned.
    """
    key = ("scope_symbols", json.dumps(scope, sort_keys=True))
    return list(_TEXTS.get(source, key, lambda: _scope_symbols(source, scope, where)))


def _scope_symbols(source: str, scope: dict, where: str) -> list:
    source = _without_inline_tests(source)
    if scope.get("module"):
        source = _module_block(source, scope["module"], where)
    kind = scope.get("kind")
    if kind == "const":
        pattern = LIMIT_NAME
        if "matching" in scope:
            if not scope.get("why"):
                raise ContractError(
                    f"{where}: a scope with its own `matching` pattern states `why`"
                )
            pattern = re.compile(scope["matching"])
        found = [(match.start(), match.group(1)) for match in CONST_DEFINITION.finditer(source)]
        found.extend(
            (match.start(), match.group(1))
            for match in STATIC_DEFINITION.finditer(source)
            if not _static_holds_state(match)
        )
        names = [name for _, name in sorted(found) if pattern.search(name)]
    elif kind == "default_fn":
        names = DEFAULT_FN_DEFINITION.findall(source)
    else:
        raise ContractError(f"{where}: unknown scope kind {kind!r}")
    return list(dict.fromkeys(names))


def _skip_literal(source: str, index: int) -> int:
    """Index just past the string or character literal that starts at `index`, else `index`."""
    char = source[index]
    if char == '"':
        index += 1
        while index < len(source) and source[index] != '"':
            index += 2 if source[index] == "\\" else 1
        return index + 1
    if char == "'":
        # A character literal (`'x'`, `'\\n'`); a lifetime (`'static`) has no closing quote.
        if source[index + 1 : index + 2] == "\\":
            closing = source.find("'", index + 2)
            return closing + 1 if 0 < closing <= index + 12 else index
        if source[index + 2 : index + 3] == "'":
            return index + 3
    return index


def definition_spans(source: str, symbol: str) -> list:
    """`(start, end)` of the defining expression of every `const` or `static` item `symbol`.

    The expression runs from the `=` after the item's type to the `;` that ends the item;
    brackets, blocks, literals and line comments in between are skipped, so an array type
    (`[u8; 4]`) and a block expression are read whole. An item without a value (a trait
    constant) has the empty span at its `;`.
    """
    return list(_all_definition_spans(source).get(symbol, ()))


_ITEM_DEFINITION = re.compile(r"\b(?:const|static)\s+([A-Za-z_][A-Za-z_0-9]*)\s*:")


def _all_definition_spans(source: str) -> dict:
    """`definition_spans` of every `const` and `static` item of a text, read in one pass."""
    return _TEXTS.get(source, "definition_spans", lambda: _read_definition_spans(source))


def _read_definition_spans(source: str) -> dict:
    found: dict = {}
    length = len(source)
    for match in _ITEM_DEFINITION.finditer(source):
        spans = found.setdefault(match.group(1), [])
        index = match.end()
        depth = 0
        start = -1
        while index < length:
            char = source[index]
            if char in "([<{":
                depth += 1
            elif char in ")]}" or (char == ">" and source[index - 1] != "-"):
                depth -= 1
            elif depth <= 0 and char == ";":
                break
            elif depth <= 0 and char == "=":
                start = index + 1
                break
            index += 1
        if start < 0:
            spans.append((index, index))
            continue
        index = start
        depth = 0
        while index < length:
            char = source[index]
            if char in "\"'":
                skipped = _skip_literal(source, index)
                if skipped > index:
                    index = skipped
                    continue
            elif char == "/" and source.startswith("//", index):
                newline = source.find("\n", index)
                index = length if newline < 0 else newline
                continue
            elif char in "([{":
                depth += 1
            elif char in ")]}":
                depth -= 1
            elif char == ";" and depth <= 0:
                break
            index += 1
        spans.append((start, index))
    return found


_DEFAULT_FN_BODY = r"\bfn\s+{symbol}\s*\(\s*\)\s*->\s*[^{{;]+\{{(?P<expr>.*?)\}}"


def _scope_region(source: str, scope: dict, where: str) -> tuple:
    """`(start, end)` of the part of `source` a scope scans: the file, or its module block."""
    start = 0
    anchors = list(scope.get("module") or ())
    if not anchors:
        return 0, len(source)
    for anchor in anchors:
        position = source.find(anchor, start)
        if position < 0:
            raise ContractError(f"{where}: module `{anchor}` is not in the file")
        start = position + len(anchor)
    end = _block_end(source, start - 1)
    if end < 0:
        raise ContractError(f"{where}: module `{anchors[-1]}` is not closed")
    return start, end


def _symbol_spans(source: str, scope: dict, symbol: str, where: str) -> list:
    """Spans, in `source`, of the defining expressions of one limit inside its scope."""
    key = ("symbol_spans", scope.get("kind"), tuple(scope.get("module") or ()), symbol)
    return _TEXTS.get(source, key, lambda: _find_symbol_spans(source, scope, symbol, where))


def _find_symbol_spans(source: str, scope: dict, symbol: str, where: str) -> list:
    start, end = _scope_region(source, scope, where)
    if scope.get("kind") == "default_fn":
        pattern = _DEFAULT_FN_BODY.format(symbol=re.escape(symbol))
        spans = [match.span("expr") for match in re.finditer(pattern, source, re.DOTALL)]
    elif _is_function_symbol(scope, symbol):
        spans = function_body_spans(source, symbol)
    else:
        spans = definition_spans(source, symbol)
    return [span for span in spans if start <= span[0] and span[1] <= end]


def scope_expression(source: str, scope: dict, symbol: str, where: str) -> str:
    """The defining expression of one scanned limit as the contract pins it.

    Every definition of the name the scope scans counts (inline test modules excepted);
    several are joined by ` | ` in source order, so a second definition of the same
    name is a change as well.
    """

    def read() -> str:
        text = _without_inline_tests(source)
        return " | ".join(
            normalize(text[start:end]) for start, end in _symbol_spans(text, scope, symbol, where)
        )

    return _TEXTS.get(
        source, ("scope_expression", json.dumps(scope, sort_keys=True), symbol), read
    )


def mutate_limit(source: str, scope: dict, symbol: str, where: str) -> str | None:
    """`source` with every defining expression of one scanned limit set to another value.

    Returns None when the scope holds no definition with a value (a trait constant
    declared without one), which nothing can change.
    """
    spans = [span for span in _symbol_spans(source, scope, symbol, where) if span[0] < span[1]]
    if not spans:
        return None
    changed = source
    for start, end in reversed(spans):
        replacement = " 2" if normalize(source[start:end]) == "1" else " 1"
        changed = changed[:start] + replacement + changed[end:]
    return changed


def _owner_anchors(owner: dict) -> list:
    anchors = owner.get("anchor")
    if anchors is None:
        return []
    return [anchors] if isinstance(anchors, str) else list(anchors)


def _scope_key(scope: dict) -> tuple:
    return (scope.get("path"), tuple(scope.get("module") or ()))


def expand_scopes(root: Path, section: dict, problems: list) -> list:
    """Return every concrete scope: each file scope, and one per file of each `tree`.

    A `tree` scope scans every Rust source below a directory except test, bench,
    example and fixture files and the paths it lists under `skip` with a reason, so a
    new file of the directory is scanned too. A file whose name looks like a test or
    fixture file is still scanned when its crate compiles it outside test builds
    (`compiled_outside_tests`). A file that also has its own scope without a module
    keeps that scope. `comparisons` of the tree is passed on to each file that a
    non-test build compiles: a file every declaration gates by `cfg(test)` is scanned by
    name like the others, but has no production comparison to read.
    """
    scopes = []
    _SCAN_EPOCH[0] += 1
    explicit = {
        scope.get("path") for scope in section["scopes"] if "path" in scope and not scope.get("module")
    }
    trees = set()
    # A file with its own whole-file scope is compared like the tree it lies in.
    compared_trees = [
        scope["tree"] + "/"
        for scope in section["scopes"]
        if "tree" in scope and scope.get("comparisons") is True
    ]
    for scope in section["scopes"]:
        if "tree" not in scope:
            path = scope.get("path")
            if (
                scope.get("kind") == "const"
                and not scope.get("module")
                and isinstance(path, str)
                and any(path.startswith(tree) for tree in compared_trees)
                and not compiled_only_in_tests(root, path)
            ):
                scope = {**scope, "comparisons": True}
            scopes.append(scope)
            continue
        where = f"completeness tree {scope['tree']}"
        directory = root / scope["tree"]
        if scope.get("kind") != "const" or scope.get("module"):
            problems.append(f"{where}: a tree scope scans constants and names no module")
            continue
        if not directory.is_dir():
            problems.append(f"{where}: the directory does not exist")
            continue
        if scope["tree"] in trees:
            problems.append(f"{where}: the tree is listed twice")
            continue
        trees.add(scope["tree"])
        skipped = []
        for skip in scope.get("skip", []):
            if not skip.get("why"):
                problems.append(f"{where}: a skipped path states `why`")
            if not (root / skip.get("path", "")).exists() or not str(
                skip.get("path", "")
            ).startswith(scope["tree"] + "/"):
                problems.append(f"{where}: skipped path {skip.get('path')!r} is not below the tree")
            skipped.append(skip.get("path", ""))
        extra = {key: scope[key] for key in ("matching", "why", "comparisons") if key in scope}
        if "comparisons" in scope and scope["comparisons"] is not True:
            problems.append(f"{where}: `comparisons` is `true` or absent")
        for file in sorted(directory.rglob("*.rs")):
            relative = file.relative_to(root).as_posix()
            inner = relative[len(scope["tree"]) + 1 :]
            if relative in explicit:
                continue
            if TEST_FILE.search(inner) and not compiled_outside_tests(root, relative):
                continue
            if any(relative == path or relative.startswith(path + "/") for path in skipped):
                continue
            flags = dict(extra)
            if flags.get("comparisons") and compiled_only_in_tests(root, relative):
                del flags["comparisons"]
            scopes.append({"path": relative, "kind": "const", "tree": scope["tree"], **flags})
    return scopes


def _exclusion_entries(section: dict, problems: list) -> list:
    """Flatten the exclusion groups into `(holder, path, module, symbol)` entries.

    A group names one file (`path`, optional `module`, `symbols`) or, under one shared
    reason, several (`files`, each with `path` and `symbols`).
    """
    entries = []
    for group in section.get("excluded", []):
        holders = group["files"] if "files" in group else [group]
        where = f"completeness exclusion in {holders[0].get('path') if holders else None}"
        if not group.get("reason"):
            problems.append(f"{where}: an exclusion states its reason")
        if "files" in group and ("path" in group or "symbols" in group):
            problems.append(f"{where}: a group names `path` and `symbols`, or `files`")
        for holder in holders:
            if not holder.get("path") or not holder.get("symbols"):
                problems.append(f"{where}: an exclusion names its file and symbols")
            for symbol in holder.get("symbols", []):
                entries.append((holder, holder.get("path"), tuple(holder.get("module") or ()), symbol))
    return entries


def check_completeness(
    root: Path,
    contract: dict,
    problems: list,
    refresh: bool = False,
    notes: list | None = None,
    unlisted: list | None = None,
    scopes: list | None = None,
) -> None:
    """Every limit an owner file defines is a listed bound or excluded with a reason.

    An excluded term (`limit_terms`) records under `term_of` the limits whose expressions
    name it, and no other exclusion carries a `term_of` entry: a term is classified by
    the limit it is a part of, so its record says which limit that is.

    With `refresh`, an exclusion that matches no scanned limit is removed and reported
    in `notes` instead of failing, and `term_of` is rewritten from the source.
    `unlisted` receives `(scope, symbol)` of every limit that is neither listed nor
    excluded, for `--propose`.
    """
    section = contract.get("completeness")
    if not isinstance(section, dict) or not section.get("scopes"):
        problems.append("completeness: the contract lists the owner files it scans")
        return
    owners = [bound.get("owner", {}) for bound in contract["bounds"]]
    by_name: dict = {}
    for owner in owners:
        by_name.setdefault((owner.get("path"), owner.get("symbol"), owner.get("kind")), []).append(owner)

    def inside(scope: dict, owner: dict) -> bool:
        module = list(scope.get("module") or ())
        return owner.get("path") == scope["path"] and _owner_anchors(owner)[: len(module)] == module

    def listings(scope: dict, symbol: str) -> int:
        kind = "fn" if _is_function_symbol(scope, symbol) else "const"
        return sum(
            1 for owner in by_name.get((scope["path"], symbol, kind), ()) if inside(scope, owner)
        )

    def listed(scope: dict, symbol: str) -> bool:
        return listings(scope, symbol) > 0

    entries = _exclusion_entries(section, problems)
    excluded: dict = {}
    holders: dict = {}
    for holder, path, module, symbol in entries:
        key = ((path, module), symbol)
        if key in excluded:
            problems.append(f"completeness exclusion in {path}: `{symbol}` is excluded twice")
        excluded[key] = False
        holders[key] = holder
    for group in section.get("excluded", []):
        for holder in group["files"] if "files" in group else [group]:
            for record in ("exprs", "term_of"):
                for symbol in holder.get(record, {}):
                    if symbol not in holder.get("symbols", []):
                        if refresh:
                            continue
                        problems.append(
                            f"completeness exclusion in {holder.get('path')}: `{record}` records "
                            f"`{symbol}`, which the group does not exclude"
                        )
    if scopes is None:
        scopes = expand_scopes(root, section, problems)
    try:
        compared, terms = _compared(root, scopes)
    except ContractError as error:
        problems.append(str(error))
        return
    excluded_in_modules = {(path, symbol) for (path, module), symbol in excluded if module}
    seen = set()
    for scope in scopes:
        where = f"completeness {scope.get('path')}"
        if scope.get("module"):
            where += f" `{' '.join(scope['module'])}`"
        try:
            _require(scope, ("path", "kind"), where)
            if (_scope_key(scope), scope["kind"]) in seen:
                raise ContractError(f"{where}: the scope is listed twice")
            seen.add((_scope_key(scope), scope["kind"]))
            source = _read(root, scope["path"], where)
            named = scope_symbols(source, scope, where)
            symbols = scanned_symbols(source, scope, where, compared)
            for symbol in symbols:
                key = (_scope_key(scope), symbol)
                if symbol not in named and (scope["path"], symbol) in excluded_in_modules:
                    # Found by its use in the whole file; a module scope of the same file
                    # already classifies it and pins its expression.
                    continue
                if listed(scope, symbol):
                    if key in excluded:
                        problems.append(f"{where}: `{symbol}` is both listed and excluded")
                        excluded[key] = True
                    # A second definition of a listed name (another nested module, a
                    # shadowing item) is a limit nothing classifies.
                    if scope["kind"] == "const" and not _is_function_symbol(scope, symbol):
                        defined = len(
                            _symbol_spans(_without_inline_tests(source), scope, symbol, where)
                        )
                        if defined > listings(scope, symbol):
                            problems.append(
                                f"{where}: `{symbol}` is defined {defined} times in the scope "
                                f"and {listings(scope, symbol)} bound(s) list it; anchor a bound "
                                "at each definition"
                            )
                    continue
                if key in excluded:
                    excluded[key] = True
                    # The defining expression of an excluded limit is pinned: its reason
                    # was written for that value, so a change is reviewed again.
                    holder = holders[key]
                    observed = scope_expression(source, scope, symbol, where)
                    recorded = holder.get("exprs", {}).get(symbol)
                    if refresh:
                        if recorded != observed:
                            holder.setdefault("exprs", {})[symbol] = observed
                            if recorded is not None and notes is not None:
                                notes.append(
                                    f"{where}: the excluded limit `{symbol}` is now `{observed}`, "
                                    f"was `{recorded}`; confirm its exclusion still holds"
                                )
                    elif recorded is None:
                        problems.append(
                            f"{where}: the exclusion of `{symbol}` records no defining "
                            "expression in `exprs`; run --refresh"
                        )
                    elif recorded != observed:
                        problems.append(
                            f"{where}: the excluded limit `{symbol}` is now `{observed}`; the "
                            f"contract records `{recorded}`. Review the reason of its "
                            "exclusion, then run --refresh"
                        )
                    # A term names the limits it is a part of; nothing else does.
                    part_of = None
                    if symbol not in named and not scope.get("module"):
                        part_of = terms.get(scope["path"], {}).get(symbol)
                    stated = holder.get("term_of", {}).get(symbol)
                    if refresh:
                        if part_of is None:
                            if stated is not None:
                                del holder["term_of"][symbol]
                                if notes is not None:
                                    notes.append(
                                        f"{where}: `{symbol}` is a limit of its own now, no term; "
                                        "`term_of` removed, confirm the reason of its exclusion"
                                    )
                        elif stated != part_of:
                            holder.setdefault("term_of", {})[symbol] = part_of
                            if stated is not None and notes is not None:
                                notes.append(
                                    f"{where}: the term `{symbol}` is now part of "
                                    f"{', '.join(part_of)}, was {', '.join(stated)}; confirm its "
                                    "exclusion still holds"
                                )
                    elif part_of is None:
                        if stated is not None:
                            problems.append(
                                f"{where}: `{symbol}` records `term_of`, but it is a limit by "
                                "its own name or by a comparison of its own; classify it as "
                                "one, then run --refresh"
                            )
                    elif stated is None:
                        problems.append(
                            f"{where}: `{symbol}` is excluded as a term of "
                            f"{', '.join(part_of)} and records no `term_of`; run --refresh"
                        )
                    elif stated != part_of:
                        problems.append(
                            f"{where}: the term `{symbol}` is part of {', '.join(part_of)}; "
                            f"the contract records {', '.join(stated)}. Review the reason "
                            "of its exclusion, then run --refresh"
                        )
                    continue
                problems.append(
                    f"{where}: `{symbol}` is neither a listed bound nor excluded with a reason"
                )
                if unlisted is not None:
                    unlisted.append((scope, symbol))
        except ContractError as error:
            problems.append(str(error))
    for holder, path, module, symbol in entries:
        if excluded.get(((path, module), symbol)):
            continue
        text = (
            f"completeness: the exclusion of `{symbol}` in {path}"
            + (f" `{' '.join(module)}`" if module else "")
            + " matches no scanned limit"
        )
        if refresh:
            holder["symbols"] = [name for name in holder["symbols"] if name != symbol]
            if notes is not None:
                notes.append(text + "; removed")
        else:
            problems.append(text)
    if refresh:
        for group in section.get("excluded", []):
            for holder in group["files"] if "files" in group else [group]:
                # Keep one pinned expression per excluded symbol, in the order of `symbols`.
                pinned = holder.get("exprs", {})
                holder["exprs"] = {
                    name: pinned[name] for name in holder.get("symbols", []) if name in pinned
                }
                parts = holder.pop("term_of", {})
                parts = {name: parts[name] for name in holder.get("symbols", []) if name in parts}
                if parts:
                    holder["term_of"] = parts
            if "files" in group:
                group["files"] = [holder for holder in group["files"] if holder.get("symbols")]
        section["excluded"] = [
            group
            for group in section.get("excluded", [])
            if (group.get("files") if "files" in group else group.get("symbols"))
        ]
    check_literals(root, contract, problems, refresh, notes, unlisted, scopes)
    # Listing a bound extends the scan: a constant owner lies inside a scanned scope.
    for bound in contract["bounds"]:
        owner = bound.get("owner", {})
        if owner.get("kind") != "const":
            continue
        if not any(scope.get("kind") == "const" and inside(scope, owner) for scope in scopes):
            problems.append(
                f"{bound.get('id')}: its owner in {owner.get('path')} is outside every "
                "completeness scope"
            )


def _site_records(contract: dict) -> list:
    """Every record of the contract that may name enforcement sites."""
    records = list(contract.get("bounds", []))
    for key in ("derived", "declared", "relations", "stage_tests", "behaviors"):
        records.extend(contract.get(key, []))
    return records


def literal_scopes(scopes: list) -> list:
    """The paths of the `comparisons` scopes, each once, in scope order."""
    paths = [
        scope["path"]
        for scope in scopes
        if scope.get("comparisons") and scope.get("kind") == "const" and not scope.get("module")
    ]
    return list(dict.fromkeys(paths))


def _held_whole(contains: str, text: str) -> int:
    """How often the enforcement text `contains` holds the comparison `text` whole.

    An occurrence counts when no name, number or method chain runs on at either end:
    `len > 128` is not held by `len > 1280`, and `o.len() > 128` is not held by
    `foo.len() > 128`. So a site of a bound owns the comparison it quotes and no
    shorter one that happens to be a part of its text.
    """
    count = 0
    start = contains.find(text)
    while start >= 0:
        end = start + len(text)
        before, after = contains[start - 1 : start] if start else "", contains[end : end + 1]
        head_joined = (text[0].isalnum() or text[0] == "_") and (
            before.isalnum() or before in ("_", ".")
        )
        tail_joined = (text[-1].isalnum() or text[-1] == "_") and (after.isalnum() or after == "_")
        if not head_joined and not tail_joined:
            count += 1
        start = contains.find(text, start + 1)
    return count


def check_literals(
    root: Path,
    contract: dict,
    problems: list,
    refresh: bool = False,
    notes: list | None = None,
    unlisted: list | None = None,
    scopes: list | None = None,
) -> None:
    """Every literal site of a `comparisons` scope belongs to a bound or is pinned with a reason.

    A literal site (`comparison_scan`) is covered when an enforcement site of a listed
    record of the same file holds its text whole (`_held_whole`); the bound's own site
    check then pins it.
    Every other occurrence is recorded under `completeness.literals`, in a group with a
    reason, as `text: count` of its file. A site that is not recorded, a recorded text
    that occurs a different number of times and a recorded text that is gone each fail.
    With `refresh`, counts are rewritten and vanished texts removed, both reported in
    `notes`; a new site is never added, because it needs a reason. `unlisted` receives
    `(path, text, count)` of every site that is not recorded, for `--propose`.
    """
    section = contract.get("completeness") or {}
    if scopes is None:
        scopes = expand_scopes(root, section, [])
    paths = literal_scopes(scopes)
    literals = section.get("literals")
    if not paths:
        if literals is not None:
            problems.append("completeness literals: no scope sets `comparisons`")
        return
    if not isinstance(literals, dict):
        problems.append(
            "completeness: a scope sets `comparisons`; `literals` records the literal "
            "comparisons that no bound owns"
        )
        return
    minimum = literals.get("minimum")
    if type(minimum) is not int or minimum < 2 or not literals.get("why"):
        problems.append(
            "completeness literals: `minimum` is an integer of 2 or more and `why` states "
            "why a smaller literal is not a limit"
        )
        return
    pinned: dict = {}
    for group in literals.get("groups", []):
        holders = group.get("files", [])
        where = f"completeness literals in {holders[0].get('path') if holders else None}"
        if not group.get("reason"):
            problems.append(f"{where}: a group states its reason")
        if not holders:
            problems.append(f"{where}: a group names its files")
        for holder in holders:
            path = holder.get("path")
            sites = holder.get("sites")
            if not path or not isinstance(sites, dict) or not sites:
                problems.append(f"{where}: a file names its `path` and its `sites`")
                continue
            if path not in paths:
                problems.append(
                    f"completeness literals in {path}: the file is not in a `comparisons` scope"
                )
                continue
            for text, count in sites.items():
                if (path, text) in pinned:
                    problems.append(f"completeness literals in {path}: `{text}` is recorded twice")
                if type(count) is not int or count < 1:
                    problems.append(
                        f"completeness literals in {path}: the count of `{text}` is a positive integer"
                    )
                pinned[(path, text)] = holder
    owned: dict = {}
    for record in _site_records(contract):
        for site in record.get("enforcement", []):
            if "path" in site and "contains" in site:
                owned.setdefault(site["path"], []).append(
                    (normalize(site["contains"]), site.get("count", 1))
                )
    matched = set()
    for path in paths:
        where = f"completeness literals in {path}"
        try:
            source = _read(root, path, where)
        except ContractError as error:
            problems.append(str(error))
            continue
        for text, occurrences in literal_occurrences(source, minimum).items():
            covered = sum(
                count * _held_whole(contains, text) for contains, count in owned.get(path, ())
            )
            free = occurrences - covered
            holder = pinned.get((path, text))
            if free <= 0:
                if holder is not None:
                    matched.add((path, text))
                    if refresh:
                        del holder["sites"][text]
                        if notes is not None:
                            notes.append(f"{where}: `{text}` is a site of a listed bound; removed")
                    else:
                        problems.append(
                            f"{where}: `{text}` is a site of a listed bound and recorded here too"
                        )
                continue
            if holder is None:
                problems.append(
                    f"{where}: the literal comparison `{text}` ({free} time(s)) is neither a "
                    "site of a listed bound nor recorded with a reason"
                )
                if unlisted is not None:
                    unlisted.append((path, text, free))
                continue
            matched.add((path, text))
            recorded = holder["sites"][text]
            if recorded != free:
                if refresh:
                    holder["sites"][text] = free
                    if notes is not None:
                        notes.append(
                            f"{where}: `{text}` now occurs {free} time(s), was {recorded}; "
                            "confirm the change was meant"
                        )
                else:
                    problems.append(
                        f"{where}: `{text}` occurs {free} time(s) outside the sites of listed "
                        f"bounds; the contract records {recorded}"
                    )
    for (path, text), holder in pinned.items():
        if (path, text) in matched or path not in paths:
            continue
        message = f"completeness literals in {path}: `{text}` matches no literal comparison"
        if refresh:
            holder["sites"].pop(text, None)
            if notes is not None:
                notes.append(message + "; removed")
        else:
            problems.append(message)
    if refresh:
        for group in literals.get("groups", []):
            group["files"] = [holder for holder in group.get("files", []) if holder.get("sites")]
        literals["groups"] = [group for group in literals.get("groups", []) if group.get("files")]


def _group_end(source: str, open_index: int, opening: str, closing: str) -> int:
    """Index just past the group opened at `open_index`, or -1; string literals are skipped."""
    depth = 0
    index = open_index
    length = len(source)
    while index < length:
        char = source[index]
        if char == '"':
            index += 1
            while index < length and source[index] != '"':
                index += 2 if source[index] == "\\" else 1
        elif char == opening:
            depth += 1
        elif char == closing:
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    return -1


def _function_body(source: str, function: str, where: str, path: str) -> str:
    """The body of `fn function(..) {..}` without line comments."""
    start = source.find(f"fn {function}(")
    if start < 0:
        raise ContractError(f"{where}: `{function}` is not in {path}")
    # The body opens at the first `{` after the parameter list.
    parameters = _group_end(source, source.index("(", start), "(", ")")
    body = source.find("{", parameters) if parameters > 0 else -1
    end = _block_end(source, body) if body >= 0 else -1
    if end < 0:
        raise ContractError(f"{where}: `{function}` is not closed")
    return LINE_COMMENT.sub("", source[body:end])


def _policy_push_fields(body: str, where: str) -> list:
    """Field names of every `policy.push(name, ..)` call, in source order.

    A name is a string literal, or the first element of the tuples of the literal
    table a `for (name, ..) in [..] { .. }` loop around the call iterates. Any other
    call fails: a field the checker cannot name is a field it cannot classify.
    """
    fields = []
    for call in re.finditer(r"policy\s*\.\s*push\s*\(\s*", body):
        rest = body[call.end() :]
        literal = re.match(r"\"([^\"]+)\"", rest)
        if literal:
            fields.append(literal.group(1))
            continue
        unreadable = ContractError(
            f"{where}: a `policy.push(` call binds a field whose name the checker cannot "
            f"read (`{' '.join(rest[:48].split())}`)"
        )
        variable = re.match(r"([a-z_][a-z0-9_]*)\s*,", rest)
        if variable is None:
            raise unreadable
        loops = list(
            re.finditer(
                rf"\bfor\s*\(\s*{variable.group(1)}\s*,[^)]*\)\s*in\s*\[", body[: call.start()]
            )
        )
        if not loops:
            raise unreadable
        table_open = loops[-1].end() - 1
        table_end = _group_end(body, table_open, "[", "]")
        block = re.match(r"\s*\{", body[table_end:]) if table_end > 0 else None
        if block is None or _block_end(body, table_end + block.end() - 1) < call.start():
            raise unreadable
        table = body[table_open + 1 : table_end - 1]
        index = 0
        names = []
        while True:
            opening = table.find("(", index)
            if opening < 0:
                break
            closing = _group_end(table, opening, "(", ")")
            entry = re.match(r"\(\s*\"([^\"]+)\"\s*,", table[opening:closing]) if closing > 0 else None
            if entry is None:
                raise unreadable
            names.append(entry.group(1))
            index = closing
        if not names:
            raise unreadable
        fields.extend(names)
    return fields


def _zk_policy_put_fields(body: str, where: str) -> list:
    """Field names of every `zk_policy_put_*(&mut h, "name", ..)` call, in source order.

    The domain separator (`zk_policy_put_bytes(&mut h, b"..")`) is not a field; any
    other call without a literal name fails.
    """
    fields = []
    for call in re.finditer(r"\bzk_policy_put_(\w+)\s*\(\s*&mut\s+h\s*,\s*", body):
        rest = body[call.end() :]
        literal = re.match(r"\"([^\"]+)\"", rest)
        if literal:
            fields.append(literal.group(1))
        elif not (call.group(1) == "bytes" and re.match(r"b\"[^\"]*\"\s*\)", rest)):
            raise ContractError(
                f"{where}: a `zk_policy_put_{call.group(1)}(` call binds a field whose "
                f"name the checker cannot read (`{' '.join(rest[:48].split())}`)"
            )
    return fields


def _split_top_level(text: str) -> list:
    """Split `text` at commas outside every `()`, `[]`, `<>` and `{}` group."""
    parts = []
    depth = 0
    start = 0
    for index, char in enumerate(text):
        if char in "([<{":
            depth += 1
        elif char in ")]>}":
            depth -= 1
        elif char == "," and depth == 0:
            parts.append(text[start:index])
            start = index + 1
    parts.append(text[start:])
    return parts


def struct_field_tree(source: str, name: str, where: str, seen: tuple = ()) -> list:
    """Dotted leaf field paths of `struct name { .. }`, in declaration order.

    A field whose type is another struct of the same file (also inside `Vec<..>` or
    `Option<..>`) contributes that struct's fields below its own name.
    """
    definition = re.search(rf"\bstruct\s+{re.escape(name)}\s*\{{", source)
    if definition is None:
        raise ContractError(f"{where}: struct `{name}` is not defined in the file")
    end = _block_end(source, definition.end() - 1)
    if end < 0:
        raise ContractError(f"{where}: struct `{name}` is not closed")
    body = LINE_COMMENT.sub("", source[definition.end() : end - 1])
    body = re.sub(r"#\[[^\]]*\]", "", body)
    fields = []
    for part in _split_top_level(body):
        field = re.fullmatch(
            r"\s*(?:pub(?:\([^)]*\))?\s+)?([a-z_][a-z0-9_]*)\s*:\s*(.+?)\s*", part, re.DOTALL
        )
        if field is None:
            if part.strip():
                raise ContractError(f"{where}: cannot read a field of `{name}`: `{part.strip()[:40]}`")
            continue
        inner = field.group(2)
        while True:
            wrapped = re.fullmatch(r"(?:Vec|Option)\s*<\s*(.+?)\s*>", inner, re.DOTALL)
            if wrapped is None:
                break
            inner = wrapped.group(1)
        nested = (
            re.fullmatch(r"[A-Z]\w*", inner)
            and inner not in seen
            and inner != name
            and re.search(rf"\bstruct\s+{inner}\s*\{{", source)
        )
        if nested:
            fields.extend(
                f"{field.group(1)}.{leaf}"
                for leaf in struct_field_tree(source, inner, where, (*seen, name))
            )
        else:
            fields.append(field.group(1))
    return fields


def catalog_fields(source: str, catalog: dict, where: str) -> list:
    """Return the field names an authoritative typed catalog binds, in source order.

    `policy_push` and `zk_policy_put` read the calls of the named function;
    `struct_tree` reads the fields of the named struct and of the structs it nests,
    and, when a `function` is named, checks that the function builds that struct.
    """
    reader = {key: catalog.get(key) for key in ("field_form", "function", "struct", "path")}
    key = ("catalog_fields", json.dumps(reader, sort_keys=True), where)
    return list(_TEXTS.get(source, key, lambda: _catalog_fields(source, catalog, where)))


def _catalog_fields(source: str, catalog: dict, where: str) -> list:
    form = catalog.get("field_form")
    if form not in CATALOG_FORMS:
        raise ContractError(f"{where}: unknown field form {form!r}")
    if form == "struct_tree":
        _require(catalog, ("struct",), where)
        if "function" in catalog:
            body = _function_body(source, catalog["function"], where, catalog["path"])
            if not re.search(rf"\b{re.escape(catalog['struct'])}\s*\{{", body):
                raise ContractError(
                    f"{where}: `{catalog['function']}` no longer builds `{catalog['struct']}`"
                )
        return struct_field_tree(source, catalog["struct"], where)
    _require(catalog, ("function",), where)
    body = _function_body(source, catalog["function"], where, catalog["path"])
    if form == "policy_push":
        return _policy_push_fields(body, where)
    return _zk_policy_put_fields(body, where)


ZK_VALIDITY_POLICY_SOURCE = "crates/iroha_data_model/src/zk_validity_policy.rs"
_ZK_POLICY_COMMITTED_AS = re.compile(
    r"^zk_validity_policy_v1 \(ZkValidityPolicyV1\.([a-z0-9_]+)\.([a-z0-9_]+)\)"
)


def zk_validity_policy_fields(source: str) -> dict:
    """Section name -> field names of `ZkValidityPolicyV1`, read from its definition."""
    top = re.search(r"pub struct ZkValidityPolicyV1 \{(.*?)\n\}", source, re.S)
    if top is None:
        return {}
    section_type = dict(re.findall(r"pub ([a-z0-9_]+): ([A-Za-z0-9]+),", top.group(1)))
    struct_fields: dict = {}
    for block in re.finditer(r"policy_section! \{(.*?)\n\}", source, re.S):
        body = re.sub(r"//[^\n]*", "", block.group(1))
        name = re.search(r"\b(Zk[A-Za-z0-9]+)\s*\{", body)
        if name is None:
            continue
        inner = body[name.end():]
        struct_fields[name.group(1)] = re.findall(r"^\s*([a-z0-9_]+)\s*:", inner, re.M)
    return {section: struct_fields.get(kind, []) for section, kind in section_type.items()}


def check_zk_policy_committed_as(root: Path, contract: dict, problems: list) -> None:
    """A bound committed as a field of the ZK validity policy names a field that exists."""
    named = [
        (bound, _ZK_POLICY_COMMITTED_AS.match(bound.get("committed_as") or ""))
        for bound in contract["bounds"]
        if str(bound.get("committed_as", "")).startswith("zk_validity_policy_v1")
    ]
    if not named:
        return
    try:
        fields = zk_validity_policy_fields(
            _read(root, ZK_VALIDITY_POLICY_SOURCE, "ZK validity policy")
        )
    except ContractError as error:
        problems.append(str(error))
        return
    for bound, match in named:
        where = f"bound {bound.get('id')}"
        if match is None:
            problems.append(
                f"{where}: `committed_as` must start with "
                "`zk_validity_policy_v1 (ZkValidityPolicyV1.<section>.<field>)`"
            )
            continue
        section, field = match.groups()
        if field not in fields.get(section, []):
            problems.append(
                f"{where}: `committed_as` names ZkValidityPolicyV1.{section}.{field}, which "
                f"{ZK_VALIDITY_POLICY_SOURCE} does not define"
            )


PIPELINE_VALIDITY_POLICY_SOURCE = "crates/iroha_data_model/src/pipeline_validity_policy.rs"
_PIPELINE_POLICY_COMMITTED_AS = re.compile(
    r"^pipeline_validity_policy_v1 \(PipelineValidityPolicyV1\.([a-z0-9_]+)\)"
)


def pipeline_validity_policy_fields(source: str) -> list:
    """Field names of `PipelineValidityPolicyV1`, read from its definition."""
    block = re.search(r"\npipeline_policy! \{(.*?)\n\}", source, re.S)
    if block is None:
        return []
    body = re.sub(r"//[^\n]*", "", block.group(1))
    return re.findall(r"^\s*([a-z0-9_]+)\s*:", body, re.M)


def check_pipeline_policy_committed_as(root: Path, contract: dict, problems: list) -> None:
    """A bound committed as a field of the pipeline validity policy names a field that exists."""
    named = [
        (bound, _PIPELINE_POLICY_COMMITTED_AS.match(bound.get("committed_as") or ""))
        for bound in contract["bounds"]
        if str(bound.get("committed_as", "")).startswith("pipeline_validity_policy_v1")
    ]
    if not named:
        return
    try:
        fields = pipeline_validity_policy_fields(
            _read(root, PIPELINE_VALIDITY_POLICY_SOURCE, "pipeline validity policy")
        )
    except ContractError as error:
        problems.append(str(error))
        return
    for bound, match in named:
        where = f"bound {bound.get('id')}"
        if match is None:
            problems.append(
                f"{where}: `committed_as` must start with "
                "`pipeline_validity_policy_v1 (PipelineValidityPolicyV1.<field>)`"
            )
            continue
        field = match.group(1)
        if field not in fields:
            problems.append(
                f"{where}: `committed_as` names PipelineValidityPolicyV1.{field}, which "
                f"{PIPELINE_VALIDITY_POLICY_SOURCE} does not define"
            )


def check_catalogs(
    root: Path, contract: dict, tasks: dict, problems: list, unlisted: list | None = None
) -> None:
    """Every field of an authoritative typed catalog is a listed bound or excluded.

    A field recorded under `digests` is the digest of another catalog of this contract,
    which must exist: the fields behind the digest are classified there. `unlisted`
    receives `(catalog, field)` of every field that is not recorded, for `--propose`.
    """
    by_id = {bound.get("id"): bound for bound in contract["bounds"]}
    catalog_ids = [catalog.get("id") for catalog in contract.get("catalogs", [])]
    claimed: dict = {}
    for catalog in contract.get("catalogs", []):
        where = f"catalog {catalog.get('id', '<without id>')}"
        try:
            _require(catalog, ("id", "path", "field_form", "what", "fields", "excluded"), where)
            if catalog_ids.count(catalog["id"]) > 1:
                raise ContractError(f"{where}: duplicate catalog id")
            name = catalog.get("function") or catalog.get("struct")
            observed = catalog_fields(_read(root, catalog["path"], where), catalog, where)
            if len(set(observed)) != len(observed):
                raise ContractError(f"{where}: the source binds a field twice")
            excluded = []
            for group in catalog["excluded"]:
                if not group.get("reason"):
                    raise ContractError(f"{where}: an exclusion states its reason")
                excluded.extend(group.get("fields", []))
            digests = catalog.get("digests", {})
            for field, target in digests.items():
                if target not in catalog_ids or target == catalog["id"]:
                    problems.append(
                        f"{where}: `{field}` is recorded as the digest of `{target}`, "
                        "which is not another catalog of this contract"
                    )
            recorded = list(catalog["fields"]) + excluded + list(digests)
            for field in sorted(set(recorded)):
                if recorded.count(field) > 1:
                    problems.append(f"{where}: `{field}` is recorded twice")
            for field in observed:
                if field not in recorded:
                    problems.append(
                        f"{where}: field `{field}` of `{name}` is neither "
                        "listed as a bound nor excluded with a reason"
                    )
                    if unlisted is not None:
                        unlisted.append((catalog, field))
            for field in recorded:
                if field not in observed:
                    problems.append(f"{where}: `{field}` is not a field of `{name}`")
            for field, identifier in catalog["fields"].items():
                bound = by_id.get(identifier)
                if bound is None:
                    problems.append(f"{where}: `{field}` names unknown bound `{identifier}`")
                    continue
                if identifier in claimed:
                    problems.append(f"{identifier}: two catalog fields name this bound")
                claimed[identifier] = catalog["id"]
                if bound.get("catalog") != {"id": catalog["id"], "field": field}:
                    problems.append(
                        f"{identifier}: records `catalog` as {catalog['id']} / {field}"
                    )
                if catalog.get("source") and bound.get("source") != catalog["source"]:
                    problems.append(
                        f"{identifier}: a field of {catalog['id']} has source "
                        f"`{catalog['source']}`"
                    )
                if catalog.get("source") == "node_local" and bound.get("class") != "consensus":
                    problems.append(
                        f"{identifier}: {catalog['id']} binds validity-affecting node "
                        "configuration; the bound is classed consensus with its defect"
                    )
        except ContractError as error:
            problems.append(str(error))
    for required in REQUIRED_CATALOGS:
        if required not in catalog_ids:
            problems.append(f"catalogs: `{required}` is checked against the source")
    for bound in contract["bounds"]:
        if "catalog" in bound and claimed.get(bound.get("id")) != bound["catalog"].get("id"):
            problems.append(
                f"{bound.get('id')}: its `catalog` entry is not a field of that catalog"
            )


def check_relations(contract: dict, values: dict, tasks: dict, problems: list) -> None:
    profiles = {"today": {}}
    for name, profile in contract.get("profiles", {}).items():
        overrides = profile.get("overrides", {})
        for identifier in overrides:
            if identifier not in values:
                problems.append(f"profile {name}: unknown bound `{identifier}`")
        profiles[name] = overrides
        owner = profile.get("owner")
        if owner not in tasks:
            problems.append(f"profile {name}: owner `{owner}` is not a delivery-graph task")
    seen = set()
    for relation in contract.get("relations", []):
        where = f"relation {relation.get('id', '<without id>')}"
        try:
            _require(relation, ("id", "expr", "why", "expect"), where)
            if relation["id"] in seen:
                raise ContractError(f"{where}: duplicate relation id")
            seen.add(relation["id"])
            if "today" not in relation["expect"]:
                raise ContractError(f"{where}: `expect` records `today`")
            for profile, expected in relation["expect"].items():
                if profile not in profiles:
                    raise ContractError(f"{where}: unknown profile `{profile}`")
                if expected not in EXPECTATIONS:
                    raise ContractError(f"{where}: unknown expectation {expected!r}")
                result = evaluate_relation(
                    relation["expr"], {**values, **profiles[profile]}, where
                )
                if type(result) is not bool:
                    raise ContractError(f"{where}: the expression is not a comparison")
                actual = "holds" if result else "violated"
                if actual != expected:
                    raise ContractError(
                        f"{where}: {actual} under `{profile}`; the contract records {expected}"
                    )
            # A violated relation names the task that must make it hold. A relation
            # that holds may still carry an open item, for example an unmeasured margin.
            if "violated" in relation["expect"].values() or "open" in relation:
                _check_open_owner(relation.get("open", {}), tasks, where, problems)
        except ContractError as error:
            problems.append(str(error))


def check_declared(contract: dict, tasks: dict, problems: list) -> None:
    for declared in contract.get("declared", []):
        where = f"declared {declared.get('id', '<without id>')}"
        try:
            _require(declared, ("id", "group", "what", "status", "requires"), where)
            if declared["group"] not in GROUPS:
                raise ContractError(f"{where}: unknown group {declared['group']!r}")
            if declared["status"] != "not_implemented":
                raise ContractError(
                    f"{where}: an implemented item is a bound with an owner, not `declared`"
                )
            if not declared["requires"]:
                raise ContractError(f"{where}: a declared item lists what it must satisfy")
            _check_open_owner(declared.get("open", {}), tasks, where, problems)
        except ContractError as error:
            problems.append(str(error))


def check_budgets(
    contract: dict, values: dict, tasks: dict, problems: list, refresh: bool = False
) -> None:
    section = contract.get("ram_lfe")
    if not isinstance(section, dict) or not section.get("budgets"):
        problems.append("ram_lfe: the contract derives the RAM-LFE budgets")
        return
    # Closed budgets join `values`, so a relation can name one.
    known = values
    open_inputs = {}
    for item in section.get("open_inputs", []):
        where = f"ram_lfe input {item.get('id', '<without id>')}"
        if item.get("value") is not None:
            problems.append(f"{where}: a known input is a bound, not an open input")
        _check_open_owner(item, tasks, where, problems)
        open_inputs[item.get("id")] = item
    for budget in section["budgets"]:
        where = f"ram_lfe budget {budget.get('id', '<without id>')}"
        try:
            _require(budget, ("id", "what", "unit", "class", "formula", "inputs", "value"), where)
            if budget["class"] not in CLASSES:
                raise ContractError(f"{where}: unknown class {budget['class']!r}")
            used = set(ID.findall(budget["formula"]))
            if used != set(budget["inputs"]):
                raise ContractError(
                    f"{where}: `inputs` must be exactly the ids the formula uses: "
                    f"{sorted(used)}"
                )
            missing = [name for name in used if name not in known and name not in open_inputs]
            if missing:
                raise ContractError(f"{where}: unknown inputs {sorted(missing)}")
            still_open = sorted(name for name in used if name in open_inputs)
            # The formula must be well formed even while inputs are open.
            probe = {**known, **{name: 1 for name in open_inputs}}
            if type(evaluate_relation(budget["formula"], probe, where)) is not int:
                raise ContractError(f"{where}: the formula is not an integer expression")
            if still_open:
                if budget["value"] is not None:
                    raise ContractError(
                        f"{where}: {still_open} are open, so the value must be null; "
                        "no number is invented"
                    )
            else:
                computed = evaluate_relation(budget["formula"], known, where)
                if refresh:
                    budget["value"] = computed
                if budget["value"] != computed:
                    raise ContractError(
                        f"{where}: every input is known and the formula gives "
                        f"{computed}; the contract records {budget['value']}"
                    )
                known[budget["id"]] = computed
        except ContractError as error:
            problems.append(str(error))
    # The derivation covers the full workload: no declared input or shape is left unused.
    used_anywhere = set()
    for budget in section["budgets"]:
        used_anywhere.update(ID.findall(budget.get("formula", "")))
    for identifier in open_inputs:
        if identifier not in used_anywhere:
            problems.append(
                f"ram_lfe input {identifier}: an open input is used by a budget formula"
            )
    for bound in contract["bounds"]:
        identifier = bound.get("id", "")
        if identifier.startswith("ram_lfe.shape_") and identifier not in used_anywhere:
            problems.append(
                f"{identifier}: a RAM-LFE shape bound is used by a budget formula"
            )
    for component in WORKLOAD_COMPONENTS:
        if not any(budget.get("component") == component for budget in section["budgets"]):
            problems.append(
                f"ram_lfe: the workload component `{component}` has a budget"
            )
    for budget in section["budgets"]:
        if budget.get("component") not in WORKLOAD_COMPONENTS:
            problems.append(
                f"ram_lfe budget {budget.get('id')}: names its workload `component`"
            )


def check_derived(
    root: Path,
    contract: dict,
    values: dict,
    problems: list,
    refresh: bool = False,
    notes: list | None = None,
) -> None:
    """Recompute every derived bound from the verified bounds; add it to `values`."""
    for derived in contract.get("derived", []):
        where = f"derived {derived.get('id', '<without id>')}"
        try:
            keys = ("id", "group", "what", "unit", "class", "formula", "value")
            _require(derived, keys + ("enforcement", "tests"), where)
            if derived["group"] not in GROUPS:
                raise ContractError(f"{where}: unknown group {derived['group']!r}")
            if derived["class"] not in CLASSES:
                raise ContractError(f"{where}: unknown class {derived['class']!r}")
            if derived["id"] in values:
                raise ContractError(f"{where}: the id is already a bound")
            computed = evaluate_relation(derived["formula"], values, where)
            if type(computed) is not int:
                raise ContractError(f"{where}: the formula is not an integer expression")
            if refresh:
                derived["value"] = computed
            if computed != derived["value"]:
                raise ContractError(
                    f"{where}: the formula gives {computed}; the contract records "
                    f"{derived['value']}"
                )
            if not derived["enforcement"] or not derived["tests"]:
                raise ContractError(f"{where}: names its enforcement sites and tests")
            values[derived["id"]] = computed
        except ContractError as error:
            problems.append(str(error))
        _check_sites(root, derived, where, problems, None, refresh, notes)


BEHAVIORS = (
    "missing_local_resource_defers",
    "malformed_carried_evidence_rejects_deterministically",
)
# Stages a behavior's tests must reach: each test names the stage it exercises.
BEHAVIOR_STAGES = {
    "missing_local_resource_defers": ("queue", "proposer", "follower"),
    "malformed_carried_evidence_rejects_deterministically": ("sdk", "queue", "follower"),
}


def check_stage_tests(
    root: Path,
    contract: dict,
    tasks: dict,
    problems: list,
    refresh: bool = False,
    notes: list | None = None,
) -> None:
    """Every stage names its exact and one-over tests, or the task that owns the gap."""
    covered = set()
    for entry in contract.get("stage_tests", []):
        where = f"stage_tests {entry.get('stage')}"
        if entry.get("stage") not in STAGES:
            problems.append(f"{where}: unknown stage")
            continue
        covered.add(entry["stage"])
        _check_sites(root, entry, where, problems, None, refresh, notes)
        if not entry.get("claim"):
            problems.append(f"{where}: states its claim")
        if "open" in entry:
            _check_open_owner(entry["open"], tasks, where, problems)
        elif not entry.get("tests"):
            problems.append(f"{where}: names a test or the task that owns the gap")
    for stage in STAGES:
        if stage not in covered:
            problems.append(f"stage_tests: stage `{stage}` is missing")
    behaviors = {entry.get("id"): entry for entry in contract.get("behaviors", [])}
    for identifier in BEHAVIORS:
        entry = behaviors.get(identifier)
        if entry is None or not entry.get("tests"):
            problems.append(f"behaviors: `{identifier}` names the tests that show it")
            continue
        _check_sites(root, entry, f"behaviors {identifier}", problems, None, refresh, notes)
        if "open" in entry:
            _check_open_owner(entry["open"], tasks, f"behaviors {identifier}", problems)
        reached = {test.get("stage") for test in entry["tests"]}
        for stage in BEHAVIOR_STAGES[identifier]:
            if stage not in reached:
                problems.append(
                    f"behaviors: `{identifier}` names a test at the `{stage}` stage"
                )


# Keys whose text is source code, a path or a name: not prose that cites bounds.
_UNCITED_KEYS = frozenset(
    (
        "contains",
        "expr",
        "formula",
        "path",
        "symbol",
        "anchor",
        "committed_as",
        "macro",
        "macro_path",
        "name",
        "field",
        "function",
        "struct",
        "matching",
        "exprs",
        "features",
    )
)
_CITED_ID = re.compile(
    r"(?<![/:\w.])(?:" + "|".join(GROUPS) + r")\.[a-z][a-z0-9_]*(?![\w(])"
)


def check_references(contract: dict, problems: list) -> None:
    """Every bound id a reason, note or description cites is an id of this contract.

    A reason such as "bounded by guest_memory.heap_max_bytes" is checked text: a
    renamed or removed bound must not leave a reason that cites nothing. A group
    followed by `.*` (`rs16.*`) cites the group and is not an id.
    """
    known = {bound.get("id") for bound in contract["bounds"]}
    for key in ("derived", "declared"):
        known.update(item.get("id") for item in contract.get(key, []))
    lfe = contract.get("ram_lfe") or {}
    known.update(item.get("id") for item in lfe.get("budgets", []))
    known.update(item.get("id") for item in lfe.get("open_inputs", []))
    unknown: dict = {}

    def walk(value, trail: str) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if key not in _UNCITED_KEYS:
                    walk(item, f"{trail}/{key}")
        elif isinstance(value, list):
            for item in value:
                walk(item, trail)
        elif isinstance(value, str):
            for match in _CITED_ID.finditer(value):
                cited = match.group(0)
                if cited not in known and not cited.endswith(".rs"):
                    unknown.setdefault(cited, trail)

    walk(contract, "")
    for cited, trail in sorted(unknown.items()):
        problems.append(f"{trail.lstrip('/')}: the text cites `{cited}`, which is not a bound")


def load_tasks(graph_path: Path) -> dict:
    graph = json.loads(graph_path.read_text(encoding="utf-8"))
    return {task["id"]: task.get("status", "planned") for task in graph["tasks"]}


def check(
    root: Path = ROOT,
    contract: dict | None = None,
    tasks: dict | None = None,
    refresh: bool = False,
    notes: list | None = None,
    unlisted: dict | None = None,
) -> list:
    """Return every problem found; an empty list means the contract matches the source.

    With `refresh`, `contract` is updated in place before the remaining checks run: the
    expression and value the source defines for every bound, the occurrence count of
    every site that is still present, and the exclusions that still match a limit.
    `notes` receives one line for each count changed and each exclusion removed.
    `unlisted` receives the limits (`limits`) and catalog fields (`fields`) that are
    neither listed nor excluded, for `--propose`.
    """
    problems: list = []
    # A file may have changed since the last run: the verdicts are per run.
    _REACHABLE.clear()
    _REFERENCES.clear()
    _MANIFEST_TEXT.clear()
    _SCAN_EPOCH[0] += 1
    if contract is None:
        contract = json.loads((root / CONTRACT.relative_to(ROOT)).read_text(encoding="utf-8"))
    if tasks is None:
        tasks = load_tasks(root / GRAPH.relative_to(ROOT))
    if contract.get("schema") != SCHEMA:
        return [f"schema is {contract.get('schema')!r}, expected {SCHEMA!r}"]
    if contract.get("task") not in tasks:
        problems.append("`task` names the delivery-graph task that owns the contract")
    if not isinstance(contract.get("bounds"), list) or not contract["bounds"]:
        return problems + ["the contract lists its bounds"]
    limits = None if unlisted is None else unlisted.setdefault("limits", [])
    fields = None if unlisted is None else unlisted.setdefault("fields", [])
    values = verify_bounds(root, contract, problems, refresh)
    for bound in contract["bounds"]:
        _check_sites(
            root,
            bound,
            bound.get("id", "<bound without id>"),
            problems,
            bound.get("owner"),
            refresh,
            notes,
        )
    for declared in contract.get("declared", []):
        _check_sites(
            root, declared, f"declared {declared.get('id')}", problems, None, refresh, notes
        )
    for relation in contract.get("relations", []):
        _check_sites(
            root, relation, f"relation {relation.get('id')}", problems, None, refresh, notes
        )
    check_pin_tests(root, contract, problems)
    check_classification(contract, tasks, problems)
    check_fixed(contract, values, problems)
    check_completeness(root, contract, problems, refresh, notes, limits)
    check_catalogs(root, contract, tasks, problems, fields)
    check_zk_policy_committed_as(root, contract, problems)
    check_pipeline_policy_committed_as(root, contract, problems)
    check_derived(root, contract, values, problems, refresh, notes)
    check_budgets(contract, values, tasks, problems, refresh)
    check_relations(contract, values, tasks, problems)
    check_declared(contract, tasks, problems)
    check_stage_tests(root, contract, tasks, problems, refresh, notes)
    check_references(contract, problems)
    return problems


def render(contract: dict) -> str:
    """The canonical text of the contract file."""
    return json.dumps(contract, indent=2, ensure_ascii=True) + "\n"


def mutation_sweep(root: Path, contract: dict, prefixes: tuple = ()) -> tuple:
    """Change every scanned limit in memory, one at a time, and report what goes unnoticed.

    For each limit of each completeness scope (optionally only the scopes whose path
    starts with one of `prefixes`) the source text is replaced in memory by a copy in
    which the limit's defining expression is another value, and the owner and
    completeness checks run against it. A listed bound must report a changed expression
    or value, an excluded limit a changed pinned expression. In a `comparisons` scope
    the limits the code compares are changed as well, and every recorded literal site
    has its literal raised by one, which must be reported for that text. Nothing is
    written to disk.

    Returns `(changed, survivors, constant_only)`: how many limits and literals were
    changed, the `path: symbol` (or `path: literal` with the site text) of each change no check
    reported, and the limits that have no value to change in their scope (a trait
    constant declared without one).
    """
    section = contract["completeness"]
    baseline: list = []
    verify_bounds(root, contract, baseline)
    check_completeness(root, contract, baseline)
    if baseline:
        raise ContractError(
            "the mutation sweep starts from a contract that matches the source; "
            f"{len(baseline)} problem(s), first: {baseline[0]}"
        )
    changed = 0
    survivors: list = []
    constant_only: list = []
    scopes = expand_scopes(root, section, [])
    compared = compared_symbols(root, scopes)
    minimum = (section.get("literals") or {}).get("minimum")
    for path in literal_scopes(scopes) if type(minimum) is int else ():
        if prefixes and not any(path.startswith(prefix) for prefix in prefixes):
            continue
        where = f"mutation {path}"
        source = _read(root, path, where)
        for text, spans in literal_sites(source, minimum).items():
            for start, end, value in spans:
                mutated = source[:start] + str(value + 1) + source[end:]
                _OVERRIDES[path] = mutated
                try:
                    problems: list = []
                    check_literals(root, contract, problems, scopes=scopes)
                    _check_owned_sites(root, contract, path, problems)
                finally:
                    del _OVERRIDES[path]
                    _TEXTS.forget(mutated)
                changed += 1
                if not any(f"`{text}`" in problem or text in problem for problem in problems):
                    survivors.append(f"{path}: literal `{text}`")
    for scope in scopes:
        path = scope["path"]
        if prefixes and not any(path.startswith(prefix) for prefix in prefixes):
            continue
        where = f"mutation {path}"
        source = _read(root, path, where)
        for symbol in scanned_symbols(source, scope, where, compared):
            mutated = mutate_limit(source, scope, symbol, where)
            label = f"{path}: {symbol}"
            if scope.get("module"):
                label += f" in `{' '.join(scope['module'])}`"
            if mutated is None:
                constant_only.append(label)
                continue
            _OVERRIDES[path] = mutated
            try:
                problems: list = []
                verify_bounds(root, contract, problems)
                check_completeness(root, contract, problems, scopes=scopes)
            finally:
                del _OVERRIDES[path]
                _TEXTS.forget(mutated)
            changed += 1
            if not any(f"`{symbol}`" in problem for problem in problems):
                survivors.append(label)
    return changed, survivors, constant_only


def _check_owned_sites(root: Path, contract: dict, path: str, problems: list) -> None:
    """The site checks of every record that names an enforcement site in `path`."""
    for record in _site_records(contract):
        sites = [site for site in record.get("enforcement", []) if site.get("path") == path]
        if sites:
            where = str(record.get("id", record.get("stage", "<record>")))
            _check_sites(root, {"enforcement": sites}, where, problems, record.get("owner"))


def _package_name(crate: Path) -> str:
    manifest = (crate / "Cargo.toml").read_text(encoding="utf-8")
    name = re.search(r"^\[package\]\s*$.*?^name\s*=\s*\"([^\"]+)\"", manifest, re.MULTILINE | re.DOTALL)
    return name.group(1) if name else crate.name


def _test_target(crate: Path, file: Path, seen: frozenset = frozenset()) -> str | None:
    """`--lib` or `--test NAME` for the crate target that compiles a test file."""
    key = str(file)
    if key in seen:
        return None
    seen = seen | {key}
    parts = file.relative_to(crate).parts
    manifest = (crate / "Cargo.toml").read_text(encoding="utf-8")
    relative = "/".join(parts)
    for block in re.split(r"^\[\[", manifest, flags=re.MULTILINE)[1:]:
        kind = block.split("]]", 1)[0]
        block = block.split("\n[", 1)[0]
        if kind == "test" and re.search(rf"^path\s*=\s*\"{re.escape(relative)}\"", block, re.MULTILINE):
            name = re.search(r"^name\s*=\s*\"([^\"]+)\"", block, re.MULTILINE)
            return f"--test {name.group(1)}" if name else None
    if parts[0] == "src" and len(parts) == 2 and parts[1] in ("lib.rs", "main.rs"):
        return "--lib" if parts[1] == "lib.rs" else "--bins"
    if (
        parts[0] == "tests"
        and len(parts) == 2
        and not re.search(r"^\s*autotests\s*=\s*false", manifest, re.MULTILINE)
    ):
        return f"--test {file.stem}"
    module, directory = file.stem, file.parent
    if file.name == "mod.rs":
        module, directory = directory.name, directory.parent
    referrers = []
    ancestor = directory
    for _ in range(4):
        if crate not in (ancestor, *ancestor.parents):
            break
        for parent in (
            ancestor / "mod.rs",
            ancestor.parent / f"{ancestor.name}.rs",
            ancestor / "lib.rs",
            ancestor / "main.rs",
        ):
            if parent != file and _declares_module(parent, module):
                referrers.append(parent)
        ancestor = ancestor.parent
    referrers.extend(referrer for referrer in _referrers_by_path(crate, file) if referrer != file)
    for referrer in referrers:
        target = _test_target(crate, referrer, seen)
        if target is not None:
            return target
    return None


def test_commands(root: Path, contract: dict) -> list:
    """One cargo command per crate target and feature set that runs every named Rust test.

    The commands are derived from the test records and the source, like `features`.
    """
    groups: dict = {}

    def walk(value) -> None:
        if isinstance(value, dict):
            tests = value.get("tests")
            if isinstance(tests, list):
                for test in tests:
                    if isinstance(test, dict) and str(test.get("path", "")).endswith(".rs"):
                        file = root / test["path"]
                        crate = _crate_of(root, file)
                        if crate is None or not file.is_file():
                            continue
                        target = _test_target(crate, file) or "--lib"
                        features = ",".join(test.get("features", []))
                        key = (_package_name(crate), target, features)
                        groups.setdefault(key, set()).add(test["name"])
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(contract)
    commands = []
    for (package, target, features), names in sorted(groups.items()):
        command = f"cargo test --locked -p {package}"
        if features:
            command += f" --features {features.replace('|', ',')}"
        commands.append(f"{command} {target} -- {' '.join(sorted(names))}")
    return commands


# What marks a line as comparing or applying a limit, for `--propose`.
APPLICATION = re.compile(
    r"[<>]=?|[=!]=|\.\s*(?:min|max|clamp|contains|saturating_sub|checked_sub)\s*\("
    r"|\b(?:try_reserve\w*|with_capacity|to_bytes_bounded|take)\s*\("
)


def _crate_files(root: Path, relative: str, search_in: list) -> list:
    """Rust sources of the crate that owns `relative` and of every `search_in` directory."""
    file = root / relative
    crate = _crate_of(root, file)
    directories = [crate if crate is not None else file.parent]
    directories.extend(root / directory for directory in search_in)
    files = []
    for directory in directories:
        for path in sorted(directory.rglob("*.rs")):
            if "target" not in path.relative_to(root).parts and path not in files:
                files.append(path)
    return files


def propose_entry(
    root: Path,
    scope: dict,
    symbol: str,
    values: dict,
    search_in: list,
    words: tuple = (),
    limit: int = 6,
) -> dict:
    """A bound skeleton for one unlisted limit: its owner, value, candidate sites and tests.

    Sites are lines that mention the symbol (or one of `words`, for example the
    configuration field a default is read through) next to a comparison or an applying
    call; tests are active tests whose body mentions it. Both are searched in the
    owner's crate and in `search_in`. They are suggestions to review, not evidence.
    """
    where = f"{scope['path']}:{symbol}"
    kind = "fn" if _is_function_symbol(scope, symbol) else "const"
    owner: dict = {"path": scope["path"], "symbol": symbol, "kind": kind}
    if scope.get("module"):
        owner["anchor"] = list(scope["module"])
    entry: dict = {
        "id": f"<group>.{symbol.lower()}",
        "group": "<group>",
        "what": "<what the bound limits>",
        "unit": "<bytes|count|...>",
        "value": None,
        "source": "committed" if kind == "fn" else "constant",
        "class": "<consensus|local_defer|local_schedule|engineering_target>",
        "owner": owner,
    }
    try:
        owner["expr"] = extract_expression(_read(root, scope["path"], where), owner, where)
        # Resolve names through the bounds already listed for the same file.
        entry["value"] = evaluate_rust(owner["expr"], {}, values, where)
    except ContractError as error:
        entry["value_note"] = f"not evaluated: {error}; add `refs` for the constants it names"
    names = "|".join(re.escape(name) for name in (symbol, *words))
    word = re.compile(rf"\b(?:{names})\b")
    definition = re.compile(rf"\b(?:const|fn)\s+{re.escape(symbol)}\b")
    sites: list = []
    tests: list = []
    for path in _crate_files(root, scope["path"], search_in):
        text = path.read_text(encoding="utf-8")
        if not word.search(text):
            continue
        relative = path.relative_to(root).as_posix()
        production = _without_inline_tests(text)
        if not TEST_FILE.search(relative):
            for line in production.splitlines():
                code = LINE_COMMENT.sub("", line).strip()
                if (
                    word.search(code)
                    and not definition.search(code)
                    and APPLICATION.search(code.replace("->", "").replace("=>", ""))
                    and len(sites) < limit
                ):
                    site = {"stage": "<stage>", "path": relative, "contains": code}
                    count = _normalized(text).count(normalize(code))
                    if count > 1:
                        site["count"] = count
                    if site not in sites:
                        sites.append(site)
        for match in re.finditer(r"\bfn\s+(\w+)\s*\(", text):
            head = LINE_COMMENT.sub("", text[max(0, match.start() - 400) : match.start()])
            head = head[max(head.rfind("}"), head.rfind(";"), head.rfind("{")) + 1 :]
            if not TEST_ATTRIBUTE.search(head) or IGNORE_ATTRIBUTE.search(head):
                continue
            opening = text.find("{", match.end())
            end = _block_end(text, opening) if opening >= 0 else -1
            if end > 0 and word.search(text[opening:end]) and len(tests) < limit:
                tests.append({"path": relative, "name": match.group(1)})
    entry["candidate_sites"] = sites
    entry["candidate_tests"] = tests
    return entry


def propose(
    root: Path,
    contract: dict,
    tasks: dict,
    search_in: list,
    only: str | None = None,
    module: tuple = (),
    words: tuple = (),
) -> list:
    """Lines of suggestions for everything the check reports as unclassified or stale.

    Nothing is written. `only` (`PATH:SYMBOL`) asks for the skeleton of one constant
    whether or not it is listed; `module` names the nested modules that hold it and
    `words` further identifiers to search sites and tests for.
    """
    working = json.loads(json.dumps(contract))
    values: dict = {}
    verify_bounds(root, working, [], False)
    for bound in working["bounds"]:
        if "value" in bound:
            values[bound["id"]] = bound["value"]
    lines: list = []
    if only is not None:
        path, _, symbol = only.rpartition(":")
        scope = {"path": path, "kind": "const", "module": list(module)}
        entry = propose_entry(root, scope, symbol, values, search_in, words)
        return [json.dumps(entry, indent=2)]
    unlisted: dict = {}
    notes: list = []
    check(root, working, tasks, True, notes, unlisted)
    sites: dict = {}
    try:
        terms = limit_terms(root, expand_scopes(root, working["completeness"], []))
    except ContractError:
        terms = {}
    for entry in unlisted.get("limits", []):
        if len(entry) == 3:
            # A literal comparison: `(path, text, count)`.
            sites.setdefault(entry[0], {})[entry[1]] = entry[2]
            continue
        scope, symbol = entry
        lines.append(f"# unlisted limit `{symbol}` in {scope['path']}: list it or exclude it")
        part_of = None if scope.get("module") else terms.get(scope["path"], {}).get(symbol)
        if part_of is not None and symbol not in scope_symbols(
            _read(root, scope["path"], "propose"), scope, "propose"
        ):
            lines.append(
                f"#   it is a term of {', '.join(part_of)}: an exclusion records that list as "
                "`term_of` (--refresh writes it)"
            )
        lines.append(json.dumps(propose_entry(root, scope, symbol, values, search_in), indent=2))
    for path, texts in sites.items():
        lines.append(
            f"# literal comparisons of {path} that no bound owns: name them in an enforcement "
            "site of a bound, or add this file to a group of `completeness.literals`"
        )
        lines.append(json.dumps({"path": path, "sites": texts}, indent=2))
    for catalog, field in unlisted.get("fields", []):
        lines.append(
            f"# catalog {catalog['id']}: field `{field}` is not recorded; map it to a bound "
            "in `fields` or add it to an `excluded` group with the reason"
        )
    for note in notes:
        lines.append(f"# --refresh would change: {note}")
    records = [(bound.get("id"), bound) for bound in contract["bounds"]]
    for key in ("declared", "relations", "derived", "stage_tests", "behaviors"):
        records.extend((f"{key} {item.get('id', item.get('stage'))}", item) for item in contract.get(key, []))
    for where, record in records:
        for site in record.get("enforcement", []):
            try:
                source = _read(root, site["path"], str(where))
            except ContractError:
                lines.append(f"# {where}: {site['path']} does not exist")
                continue
            if normalize(site["contains"]) in _normalized(source):
                continue
            candidates = sorted({normalize(line) for line in source.splitlines()} - {""})
            close = difflib.get_close_matches(normalize(site["contains"]), candidates, 3, 0.5)
            lines.append(f"# {where}: site `{site['contains']}` is gone from {site['path']}")
            lines.extend(f"#   closest: {line}" for line in close)
    return lines


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--show", action="store_true", help="print every bound")
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="rewrite each bound's expression and value and each site's occurrence count "
        "from the source and drop exclusions that match nothing, keeping every "
        "classification; then check the result",
    )
    parser.add_argument(
        "--propose",
        action="store_true",
        help="print a bound skeleton with candidate sites and tests for every unlisted "
        "limit, the closest lines for every site that is gone and what --refresh would "
        "change; write nothing",
    )
    parser.add_argument(
        "--propose-for",
        metavar="PATH:SYMBOL",
        help="print the bound skeleton of one constant; write nothing",
    )
    parser.add_argument(
        "--search-in",
        action="append",
        default=[],
        metavar="DIR",
        help="also search this directory for candidate sites and tests (repeatable; "
        "the owner's crate is always searched)",
    )
    parser.add_argument(
        "--module",
        action="append",
        default=[],
        metavar="ANCHOR",
        help="with --propose-for: a module that holds the constant, outermost first, "
        "written as in the source, for example 'pub mod nexus {' (repeatable)",
    )
    parser.add_argument(
        "--word",
        action="append",
        default=[],
        metavar="NAME",
        help="with --propose-for: another identifier to search sites and tests for, "
        "for example the configuration field a default is read through (repeatable)",
    )
    parser.add_argument(
        "--mutate",
        nargs="*",
        metavar="PATH_PREFIX",
        help="change every scanned limit in memory, one at a time, and fail when a change "
        "goes unnoticed; with prefixes, only the limits of scopes below them; write nothing",
    )
    parser.add_argument(
        "--test-commands",
        action="store_true",
        help="print one cargo command per crate target and feature set that runs every "
        "Rust test the contract names; write nothing",
    )
    arguments = parser.parse_args(argv)
    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
    if arguments.test_commands:
        print("\n".join(test_commands(ROOT, contract)))
        return 0
    if arguments.mutate is not None:
        try:
            changed, survivors, constant_only = mutation_sweep(
                ROOT, contract, tuple(arguments.mutate)
            )
        except ContractError as error:
            print(f"error: {error}", file=sys.stderr)
            return 1
        for label in survivors:
            print(f"error: changing {label} goes unnoticed", file=sys.stderr)
        print(
            f"{changed} scanned limits and recorded literal comparisons changed in memory, "
            f"one at a time: {changed - len(survivors)} reported, {len(survivors)} unnoticed; "
            f"{len(constant_only)} have no value to change in their scope"
        )
        return 1 if survivors else 0
    if arguments.propose or arguments.propose_for:
        lines = propose(
            ROOT,
            contract,
            load_tasks(GRAPH),
            arguments.search_in,
            arguments.propose_for,
            tuple(arguments.module),
            tuple(arguments.word),
        )
        print("\n".join(lines) if lines else "nothing to propose: the contract matches the source")
        return 0
    before = render(contract)
    notes: list = []
    problems = check(contract=contract, refresh=arguments.refresh, notes=notes)
    if arguments.refresh:
        for note in notes:
            print(f"refresh: {note}")
        after = render(contract)
        if after != before:
            CONTRACT.write_text(after, encoding="utf-8")
            print(f"{CONTRACT.relative_to(ROOT)}: rewritten from the source; review the diff")
        else:
            print(f"{CONTRACT.relative_to(ROOT)}: already matches the source")
    if arguments.show:
        for bound in contract["bounds"]:
            print(
                f"{bound['id']:<52} {bound['value']:>14} {bound['unit']:<12} "
                f"{bound['source']:<10} {bound['class']}"
            )
    if problems:
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        print(f"{len(problems)} problem(s) in {CONTRACT.relative_to(ROOT)}", file=sys.stderr)
        return 1
    scopes = expand_scopes(ROOT, contract["completeness"], [])
    print(
        f"{CONTRACT.relative_to(ROOT)}: {len(contract['bounds'])} bounds, "
        f"{len(contract.get('derived', []))} derived, "
        f"{len(contract.get('relations', []))} relations, "
        f"{len(contract.get('declared', []))} declared items, "
        f"{sum(len(catalog['fields']) for catalog in contract.get('catalogs', []))} "
        f"catalog fields and {len(scopes)} scanned scopes match the source"
        + (
            f"; {recorded} recorded literal comparisons in {len(literal_scopes(scopes))} "
            "compared sources"
            if (recorded := _recorded_literals(contract))
            else ""
        )
    )
    return 0


def _recorded_literals(contract: dict) -> int:
    """How many literal comparisons `completeness.literals` records."""
    literals = (contract.get("completeness") or {}).get("literals") or {}
    return sum(
        sum(holder.get("sites", {}).values())
        for group in literals.get("groups", [])
        for holder in group.get("files", [])
    )


if __name__ == "__main__":
    raise SystemExit(main())
