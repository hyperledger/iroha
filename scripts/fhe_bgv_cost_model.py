#!/usr/bin/env python3
"""Cost model, tape planner and measurement summary of the iroha_fhe RNS-BGV candidates.

Requires Python 3.9+ and its standard library; no environment variable or
installed package is read. The tracked summary is
specs/fhe_bgv_cost_summary.json, the task C.3 output of
specs/zk_delivery_plan.md.

What this tool does:

* `--check` (the default) validates the tracked summary against the source
  tree and against itself:
  - the constants this model restates equal those of the Rust sources that own
    them (the RAM-LFE V1 shape and class limits of
    crates/iroha_crypto/src/ram_lfe/class.rs, the costing harness, the error
    parameter, the basis limit), and the pinned primes of the Rust candidates
    equal the first-prime rule;
  - every number is classified `measured`, `projection`, `parameter` or
    `estimator`;
  - what each measured run reported (geometry, sizes, operation counts, public
    noise bounds, work per opcode) equals this model;
  - every projection is recomputed from the parameters and the measured values
    the file itself carries;
  - the tracked Lattice Estimator record
    (specs/fhe_bgv_lattice_estimator_output.txt) was printed by the code
    scripts/fhe_bgv_lattice_estimator.sage now holds, at the commit it pins,
    for exactly the moduli, dimensions and distributions of this model, with
    a passing self-check; and `security_estimate` of the summary is the
    restatement of that record;
  - the tables the specifications embed and the view that a Rust test reads
    (crates/iroha_fhe/tests/vectors/bgv_cost_model_v1.txt) are the renderings
    of the summary.
  It needs no measurement log, and neither SageMath nor the estimator.
* `--build RUN_DIR [RUN_DIR ...] --manifest-sha256 SHA256 [SHA256 ...]`
  reads externally pinned accepted run directories of
  scripts/zk_resource_harness.py (under the ignored dist/zk-resource-harness/)
  through its verified-document reader, without reopening evidence paths,
  and prints the summary; with `--write` it replaces the tracked file, the
  view and the embedded tables.
* `--rederive` recomputes every derived block from the measured runs the
  tracked summary already holds and from the tracked estimator record, for a
  changed model or a new estimator run without new measurements.
* `--plan` prints the noise plans, the tape plans and the security sanity numbers.
* `--tables` prints the embedded tables.

Two implementations stand behind the modelled numbers. The Rust crate owns the
noise rules, the work-unit model, the frame sizes and the costing harness that
lowers the tape instructions; this script holds an independent model of each.
`--check` holds the summary to this model, and
`cargo test -p iroha_fhe --test bgv_cost_model_vectors` holds the view of the
summary to the Rust one, so the two have to agree on every number of the view:
candidate and profile geometry, sizes, work units, per-instruction costs, the
plan of every maximum-shape tape family, the fewest primes each needs, the
longest chains that fit and the resource-contract inputs. The proof-work
projections, the affine-map proposal and the core-SVP sanity numbers are
computed here only.

Classification:

* `measured`: copied from an accepted harness record of this host (phase wall
  times, sizes and counts the instrumented code reported, process peak RSS),
  or a sum, a ratio or an extreme of such values.
* `projection`: computed by this script from profile parameters, by the
  worst-case noise rules of crates/iroha_fhe/src/bgv/noise.rs, by the work-unit
  model of crates/iroha_fhe/src/bgv/cost.rs, by the tape lowering of
  crates/iroha_fhe/tests/support/machine.rs, by a stated relation layout, by
  scaling a measured time with model units, or by the core-SVP sanity formula.
* `parameter`: an exact input that defines a profile or a workload shape, or
  an illustrative setting of a projection that nobody has selected.
* `estimator`: copied from a line of the tracked output record of
  scripts/fhe_bgv_lattice_estimator.sage, or a minimum, a count or a
  difference of such values. This script never runs the estimator.

Nothing here establishes security or qualifies a profile. The estimator
numbers are the output of one tool for plain LWE under its heuristics; what
they do not cover is listed in the summary
(`security_estimate.lattice_estimator.not_covered`). The core-SVP numbers are
this script's own sanity calculation (primal uSVP under the geometric series
assumption, one cost exponent per model) and are kept beside the estimator's
for comparison. An attack the record has no cost for is reported with the
reason, never as a cost. The flooding and proof-work figures are projections
of constructions that do not exist.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import re
import sys
from pathlib import Path
from typing import Any, Optional

ROOT = Path(__file__).resolve().parents[1]
_HARNESS_SPEC = importlib.util.spec_from_file_location(
    "bgv_cost_resource_harness", Path(__file__).with_name("zk_resource_harness.py")
)
assert _HARNESS_SPEC is not None and _HARNESS_SPEC.loader is not None
HARNESS = importlib.util.module_from_spec(_HARNESS_SPEC)
_HARNESS_SPEC.loader.exec_module(HARNESS)
REFERENCE_DIRECTORY = "crates/iroha_fhe/tests/vectors"
VECTORS_TEST = "crates/iroha_fhe/tests/bgv_vectors.rs"
SUMMARY_PATH = "specs/fhe_bgv_cost_summary.json"
MODEL_VECTORS_PATH = "crates/iroha_fhe/tests/vectors/bgv_cost_model_v1.txt"
PROFILE_SOURCE = "crates/iroha_fhe/src/bgv/profile.rs"
CLASS_SOURCE = "crates/iroha_crypto/src/ram_lfe/class.rs"
HARNESS_SOURCE = "crates/iroha_fhe/tests/support/machine.rs"
COINS_SOURCE = "crates/iroha_fhe/src/bgv/coins.rs"
CHAIN_SOURCE = "crates/iroha_fhe/src/rns_chain.rs"
ESTIMATOR_SCRIPT = "scripts/fhe_bgv_lattice_estimator.sage"
ESTIMATOR_OUTPUT = "specs/fhe_bgv_lattice_estimator_output.txt"
SCHEMA = "iroha.fhe.bgv_cost_summary.v2"
ERROR_ETA = 21
CLASSES = ("measured", "projection", "parameter", "estimator")

# RAM-LFE V1 shape. crates/iroha_crypto/src/ram_lfe/class.rs is authoritative; `--check`
# compares every value below with that file and with the costing harness.
PLAINTEXT_MODULUS = 257
REGISTERS = 4
STATE_LANES = 32
INPUT_SLOTS = 64
MAX_OUTPUTS = 64
MAX_INSTRUCTIONS = 256
BOUNDED_MAX_RANK = 16
REFRESH_MAX_RANK_BETWEEN_REFRESHES = 16
REFRESH_MAX_REFRESHES = 64
SELECT_MULTIPLICATIONS = 10
SELECT_BRANCH_RANK = 1
SELECT_SQUARINGS = 8
OPCODES = (
    "LoadInput",
    "LoadState",
    "StoreState",
    "LoadConst",
    "Add",
    "AddPlain",
    "SubPlain",
    "MulPlain",
    "Mul",
    "SelectEqZero",
    "Output",
)
AFFINE_OPCODES = (0, 1, 2, 3, 4, 5, 6, 7, 10)
# Largest number of primes of one basis in crates/iroha_fhe/src/rns_chain.rs.
MAX_BASIS_PRIMES = 64
# Projected flooding sanitizations: (log2 of the adaptive releases, statistical parameter).
# Illustrative values of the design memo; nobody has selected them.
SANITIZATION_PROJECTIONS = ((20, 80), (20, 40))

# ---------------------------------------------------------------------------
# Number theory and profiles
# ---------------------------------------------------------------------------


def is_prime(n: int) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in (2, 325, 9375, 28178, 450775, 9780504, 1795265022):
        a %= n
        if a == 0:
            continue
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


_PRIME_LISTS: dict = {}


def first_primes(bits: int, step: int, count: int, skip: tuple = ()) -> list:
    """First `count` primes of exactly `bits` bits congruent to one modulo `step`, skipping `skip`."""
    # The ascending list of one (bits, step) is extended on demand and shared by every profile.
    found, candidate = _PRIME_LISTS.setdefault((bits, step), ([], ((1 << (bits - 1)) // step + 1) * step + 1))
    while True:
        out = [prime for prime in found if prime not in skip][:count]
        if len(out) == count:
            return out
        while True:
            if candidate >= 1 << bits:
                raise ValueError("no prime of the requested size")
            hit = is_prime(candidate)
            if hit:
                found.append(candidate)
            candidate += step
            _PRIME_LISTS[(bits, step)] = (found, candidate)
            if hit:
                break


def product(values) -> int:
    out = 1
    for value in values:
        out *= value
    return out


class NoiseBudgetExceeded(Exception):
    """A step of a plan exceeds the capacity of its level."""


class Profile:
    """Public geometry of one parameter set, with the Rust noise and work-unit rules."""

    def __init__(self, name: str, log_degree: int, t: int, main: tuple, special: tuple, digit_primes: int):
        self.name = name
        self.log_degree = log_degree
        self.degree = 1 << log_degree
        self.t = t
        self.main_shape = tuple(main)
        self.special_shape = tuple(special)
        self.digit_primes = digit_primes
        step = 2 * self.degree * t
        self.main = first_primes(main[0], step, main[1])
        self.special = first_primes(special[0], step, special[1], tuple(self.main))
        self.top = len(self.main) - 1
        self.special_product = product(self.special)

    def shape(self) -> dict:
        return {
            "log_degree": self.log_degree,
            "plaintext_modulus": self.t,
            "main_prime_bits": self.main_shape[0],
            "main_primes": self.main_shape[1],
            "special_prime_bits": self.special_shape[0],
            "special_primes": self.special_shape[1],
            "digit_primes": self.digit_primes,
            "error_eta": ERROR_ETA,
        }

    def modulus(self, level: int) -> int:
        return product(self.main[: level + 1])

    def capacity(self, level: int) -> int:
        return (self.modulus(level) - 1) // 2

    def digit_sizes(self, level: int) -> list:
        sizes = []
        first = 0
        while first <= level:
            sizes.append(min(self.digit_primes, level + 1 - first))
            first += self.digit_primes
        return sizes

    def digit_count(self) -> int:
        return len(self.digit_sizes(self.top))

    # Noise rules (crates/iroha_fhe/src/bgv/noise.rs) ---------------------

    def fresh_noise(self) -> int:
        return (self.t - 1) // 2 + self.t * ERROR_ETA * (2 * self.degree + 1)

    def plaintext_noise(self) -> int:
        return (self.t - 1) // 2

    def key_switch_noise(self, level: int) -> int:
        halves = 0
        first = 0
        for size in self.digit_sizes(level):
            halves += product(self.main[first : first + size]) // 2
            first += self.digit_primes
        p = self.special_product
        return (self.t * self.degree * ERROR_ETA * halves + self.t * ((p - 1) // 2) * (1 + self.degree)) // p

    def switch_down_noise(self, bound: int, level: int) -> int:
        q = self.main[level]
        return (bound + self.t * ((q - 1) // 2) * (1 + self.degree)) // q

    # Slot encoding (crates/iroha_fhe/src/bgv/encoding.rs) ----------------

    def slots(self) -> int:
        half = (self.t - 1) // 2
        two_adic = (half & -half).bit_length() - 1
        return min(1 << two_adic, self.degree)

    def slot_root(self) -> int:
        order = 2 * self.slots()
        exponent = (self.t - 1) // order
        for generator in range(2, 1 << 16):
            root = pow(generator, exponent, self.t)
            if pow(root, order // 2, self.t) == self.t - 1:
                return root
        raise ValueError("no slot root")

    def mask_l1(self) -> int:
        """Exact centered l1 norm of a single-slot idempotent: sum |S^-1 * zeta^-k|."""
        slots = self.slots()
        inverse_root = pow(self.slot_root(), -1, self.t)
        value = pow(slots, -1, self.t)
        half = (self.t - 1) // 2
        total = 0
        for _ in range(slots):
            total += self.t - value if value > half else value
            value = value * inverse_root % self.t
        return total

    def vector_l1(self) -> int:
        return self.slots() * ((self.t - 1) // 2)

    def broadcast_steps(self) -> int:
        return self.slots().bit_length() - 1

    # Work units (crates/iroha_fhe/src/bgv/cost.rs) ------------------------

    def forward_units(self) -> int:
        return self.degree // 2 * self.log_degree

    def inverse_units(self) -> int:
        return self.forward_units() + self.degree

    def conversion_units(self, digit: int, targets: int) -> int:
        return self.degree * (digit + digit * (digit - 1) // 2 + targets * digit)

    def scale_down_units(self, kept: int, dropped: int) -> int:
        return self.degree * (2 * dropped + dropped * (dropped - 1) // 2 + kept * (dropped + 2))

    def key_switch_units(self, level: int) -> int:
        limbs = level + 1
        special = len(self.special)
        extended = limbs + special
        per_digit = sum(
            self.conversion_units(size, extended - size)
            + extended * self.forward_units()
            + 2 * extended * self.degree
            for size in self.digit_sizes(level)
        )
        return per_digit + 2 * extended * self.inverse_units() + 2 * self.scale_down_units(limbs, special)

    def tensor_units(self, level: int) -> int:
        return (level + 1) * (4 * self.forward_units() + 4 * self.degree + 3 * self.inverse_units())

    def multiplication_units(self, level: int) -> int:
        return self.tensor_units(level) + self.key_switch_units(level)

    def plaintext_multiplication_units(self, level: int) -> int:
        return (level + 1) * (3 * self.forward_units() + 2 * self.degree + 2 * self.inverse_units())

    def switch_down_units(self, level: int) -> int:
        return 2 * self.scale_down_units(level, 1)

    def encryption_units(self) -> int:
        return (self.top + 1) * (self.forward_units() + 4 * self.degree + 2 * self.inverse_units())

    def decryption_units(self, level: int) -> int:
        limbs = level + 1
        return limbs * (self.forward_units() + self.degree + self.inverse_units()) + self.conversion_units(limbs, 1)

    def key_switch_scratch_bytes(self, level: int) -> int:
        extended = level + 1 + len(self.special)
        return 8 * (4 * extended - min(self.digit_sizes(level))) * self.degree

    # Sizes ----------------------------------------------------------------

    def noise_bound_words(self) -> int:
        return -(-self.capacity(self.top).bit_length() // 64)

    def ciphertext_bytes(self, level: int, components: int = 2) -> int:
        return 36 + 8 * self.noise_bound_words() + 8 * components * (level + 1) * self.degree

    def public_key_bytes(self) -> int:
        return 32 + 8 * 2 * (self.top + 1) * self.degree

    def switching_key_bytes(self) -> int:
        return 37 + 8 * self.digit_count() * 2 * (self.top + 1 + len(self.special)) * self.degree

    def evaluation_key_bytes(self, galois_keys: int) -> int:
        return (galois_keys + 1) * self.switching_key_bytes()

    def secret_key_bytes(self) -> int:
        """Custody frame: the identity and two bits per ternary coefficient."""
        return 32 + self.degree // 4

    def residue_bytes(self, level: int, components: int = 2) -> int:
        """A ciphertext held in memory: its residues without a frame."""
        return 8 * components * (level + 1) * self.degree

    def constant_l1(self) -> int:
        """Public l1 bound of a constant polynomial: (t - 1) / 2."""
        return (self.t - 1) // 2

    def total_modulus_bits(self) -> float:
        return math.log2(self.modulus(self.top)) + math.log2(self.special_product)


CANDIDATES = {
    "bgv.f257.n14.q6x50.p2x60": (14, 257, (50, 6), (60, 2), 2),
    "bgv.f257.n16.q22x50.p2x60": (16, 257, (50, 22), (60, 2), 2),
    "bgv.f257.n16.q32x50.p2x60": (16, 257, (50, 32), (60, 2), 2),
}
CANDIDATE_CLASS = {
    "bgv.f257.n14.q6x50.p2x60": "affine.v1",
    "bgv.f257.n16.q22x50.p2x60": "bounded.v1",
    "bgv.f257.n16.q32x50.p2x60": "refresh.v1",
}
# Profiles of the equal workload: harness `--config` to the profile it ran.
MEASURED_CONFIGS = {
    "bgv.f257.n16.q22x50.p2x60/sparse128": ("bgv.f257.n16.q22x50.p2x60", (16, 257, (50, 22), (60, 2), 2)),
    "bgv.derive.n16.t786433.q25x60.p3x60.d2/split65536": (
        "bgv.derive.n16.t786433.q25x60.p3x60.d2",
        (16, 786433, (60, 25), (60, 3), 2),
    ),
    "bgv.derive.n14.t257.q13x50.p2x60.d2/sparse128": (
        "bgv.derive.n14.t257.q13x50.p2x60.d2",
        (14, 257, (50, 13), (60, 2), 2),
    ),
}

# Every harness configuration of the summary: `--config` to (workload kind, profile name, shape).
RUN_CONFIGS = {config: ("equal_workload", name, shape) for config, (name, shape) in MEASURED_CONFIGS.items()}
RUN_CONFIGS.update(
    {
        # The equal workload on the non-zero branch of its select.
        "bgv.f257.n16.q22x50.p2x60/sparse128.nonzero": (
            "equal_workload",
            "bgv.f257.n16.q22x50.p2x60",
            CANDIDATES["bgv.f257.n16.q22x50.p2x60"],
        ),
        # One instruction of every opcode through the costing harness.
        "bgv.f257.n16.q22x50.p2x60/tape_profile": (
            "tape_profile",
            "bgv.f257.n16.q22x50.p2x60",
            CANDIDATES["bgv.f257.n16.q22x50.p2x60"],
        ),
        "bgv.f257.n14.q6x50.p2x60/tape_profile": (
            "tape_profile",
            "bgv.f257.n14.q6x50.p2x60",
            CANDIDATES["bgv.f257.n14.q6x50.p2x60"],
        ),
    }
)

_PROFILE_CACHE: dict = {}
_IDENTITY_CACHE: dict = {}


def profile_identity(shape: tuple) -> str:
    """The canonical profile identity, computed by the independent Python reference."""
    if shape not in _IDENTITY_CACHE:
        sys.path.insert(0, str(ROOT / REFERENCE_DIRECTORY))
        try:
            import bgv_reference  # type: ignore[import-not-found]
        finally:
            sys.path.pop(0)
        log_degree, t, main, special, digit_primes = shape
        reference = bgv_reference.Profile(log_degree, t, main[0], main[1], special[0], special[1], digit_primes)
        _IDENTITY_CACHE[shape] = reference.identity().hex()
    return _IDENTITY_CACHE[shape]


def profile(name: str, shape: tuple) -> Profile:
    key = (name, shape)
    if key not in _PROFILE_CACHE:
        _PROFILE_CACHE[key] = Profile(name, *shape)
    return _PROFILE_CACHE[key]


# ---------------------------------------------------------------------------
# Noise plans
# ---------------------------------------------------------------------------


class Plan:
    """Tracks (bound, level) pairs by the rules of the Rust evaluator."""

    def __init__(self, p: Profile):
        self.p = p
        self.steps: list = []
        self.counts = {"multiplications": 0, "key_switches": 0, "plaintext_multiplications": 0, "modulus_switches": 0}

    def _admit(self, label: str, bound: int, level: int) -> tuple:
        if bound > self.p.capacity(level):
            raise NoiseBudgetExceeded(f"{label} at level {level}: {bound.bit_length()} bits")
        return (bound, level)

    def note(self, label: str, value: tuple) -> None:
        self.steps.append({"step": label, "noise_bound_bits": value[0].bit_length(), "level": value[1]})

    def fresh(self) -> tuple:
        return self._admit("fresh", self.p.fresh_noise(), self.p.top)

    def trivial(self, level: int) -> tuple:
        return self._admit("trivial", self.p.plaintext_noise(), level)

    def add(self, lhs: tuple, rhs: tuple) -> tuple:
        assert lhs[1] == rhs[1]
        return self._admit("add", lhs[0] + rhs[0], lhs[1])

    def add_plain(self, value: tuple) -> tuple:
        return self._admit("add_plain", value[0] + self.p.plaintext_noise(), value[1])

    def mul_plain(self, value: tuple, l1: int) -> tuple:
        self.counts["plaintext_multiplications"] += 1
        return self._admit("mul_plain", value[0] * l1, value[1])

    def galois(self, value: tuple) -> tuple:
        self.counts["key_switches"] += 1
        return self._admit("galois", value[0] + self.p.key_switch_noise(value[1]), value[1])

    def switch_down(self, value: tuple) -> tuple:
        if value[1] == 0:
            raise NoiseBudgetExceeded("no level left")
        self.counts["modulus_switches"] += 1
        return self._admit("switch_down", self.p.switch_down_noise(value[0], value[1]), value[1] - 1)

    def switch_to(self, value: tuple, level: int) -> tuple:
        while value[1] > level:
            value = self.switch_down(value)
        return value

    def multiply_then_switch(self, lhs: tuple, rhs: tuple) -> tuple:
        level = min(lhs[1], rhs[1])
        lhs, rhs = self.switch_to(lhs, level), self.switch_to(rhs, level)
        self.counts["multiplications"] += 1
        self.counts["key_switches"] += 1
        tensor = self._admit("tensor", self.p.degree * lhs[0] * rhs[0], level)
        relinearized = self._admit("relinearize", tensor[0] + self.p.key_switch_noise(level), level)
        return self.switch_down(relinearized)

    def power(self, base: tuple, exponent: int) -> tuple:
        result = None
        while True:
            if exponent & 1:
                result = base if result is None else self.multiply_then_switch(result, base)
            exponent >>= 1
            if exponent == 0:
                return result
            base = self.multiply_then_switch(base, base)

    def load_input(self, encrypted: tuple) -> tuple:
        current = self.mul_plain(encrypted, self.p.mask_l1())
        for _ in range(self.p.broadcast_steps()):
            current = self.add(current, self.galois(current))
        return self.switch_down(current)


def plan_equal_workload(p: Profile) -> Plan:
    """The workload of crates/iroha_fhe/tests/bgv_cost_measurement.rs."""
    plan = Plan(p)
    encrypted = plan.fresh()
    plan.note("fresh", encrypted)
    condition = plan.load_input(encrypted)
    zero_branch = plan.load_input(encrypted)
    plan.note("load_input", condition)
    powered = plan.power(condition, p.t - 1)
    plan.note("equality_exponentiation", powered)
    powered = plan.multiply_then_switch(powered, plan.trivial(powered[1]))
    indicator = plan.add_plain(powered)
    selected = plan.add_plain(plan.multiply_then_switch(indicator, plan.add_plain(zero_branch)))
    plan.note("select_eq_zero", selected)
    condition_low = plan.switch_to(condition, selected[1])
    packed = plan.add(plan.mul_plain(selected, p.mask_l1()), plan.mul_plain(condition_low, p.mask_l1()))
    packed = plan.mul_plain(packed, p.vector_l1())
    plan.note("output", packed)
    plan.steps.append({"step": "final_capacity_bits", "noise_bound_bits": p.capacity(packed[1]).bit_length(), "level": packed[1]})
    return plan


def plan_affine_map(p: Profile) -> Plan:
    """An affine map evaluated as one row product and one trace per output (see the spec)."""
    plan = Plan(p)
    row = plan.mul_plain(plan.fresh(), p.vector_l1())
    for _ in range(p.broadcast_steps()):
        row = plan.add(row, plan.galois(row))
    row = plan.add_plain(row)
    plan.note("row_product_and_trace", row)
    row = plan.switch_down(row)
    packed = plan.mul_plain(row, p.mask_l1())
    for _ in range(MAX_OUTPUTS.bit_length() - 1):
        packed = plan.add(packed, packed)
    packed = plan.mul_plain(packed, p.vector_l1())
    plan.note("output_64_masks_and_zeroing", packed)
    return plan


def minimal_main_primes(shape: tuple, planner, limit: int = 40) -> Optional[int]:
    """Fewest main primes of the given shape on which `planner` is admitted."""
    log_degree, t, (bits, _), special, digit_primes = shape
    for count in range(1, limit + 1):
        try:
            planner(Profile("search", log_degree, t, (bits, count), special, digit_primes))
            return count
        except NoiseBudgetExceeded:
            continue
    return None


# ---------------------------------------------------------------------------
# Tape lowering (mirror of crates/iroha_fhe/tests/support/machine.rs)
# ---------------------------------------------------------------------------
#
# The eleven V1 instructions are lowered onto the scheme once, in the costing
# harness of the Rust tests, where the same code runs over public shapes and
# over ciphertexts. This is a second, independent implementation of the shape
# run of that lowering. `--check` requires the tracked summary to equal this
# recomputation, and a Rust test requires the Rust harness to equal the view
# of the summary in MODEL_VECTORS_PATH; the two implementations therefore have
# to agree on every recorded number.

LOAD_INPUT, LOAD_STATE, STORE_STATE, LOAD_CONST, ADD, ADD_PLAIN, SUB_PLAIN, MUL_PLAIN, MUL, SELECT_EQ_ZERO, OUTPUT = range(11)
FINAL_MASK = 11
WORK_FIELDS = ("plaintext_multiplications", "key_switches", "multiplications", "modulus_switches", "work_units")
PM, KS, CM, MS, UNITS = range(5)

LOWERING_TEXT = (
    "Every register and state lane holds one scalar broadcast to all slots; registers start as the noiseless"
    " embedding of zero and lanes as the noiseless embedding of their initial scalars, at the top level."
    " LoadInput multiplies the packed input by the idempotent of its slot and applies, for each broadcast"
    " element, the automorphism and an addition. LoadState and StoreState copy. LoadConst is the noiseless"
    " embedding at the top level. Add aligns and adds. AddPlain and SubPlain add or subtract the constant"
    " polynomial; MulPlain multiplies by it. Mul is one lowered product. SelectEqZero is eight lowered"
    " squarings of the condition, a lowered product with the embedded one, indicator = 1 - c^256,"
    " delta = zero - nonzero and nonzero + indicator * delta. Output multiplies by the idempotent of the next"
    " output slot and adds to the accumulator. At the end the accumulator is multiplied by the mask that"
    " zeroes every unused output slot."
)
LEVEL_POLICY_TEXT = (
    "Lazy. A value stays at its level until an operation needs otherwise. A binary operation switches the"
    " operand at the higher level down to the level of the other. Before a product both operands are switched"
    " down one prime at a time while that strictly increases the ratio of the level capacity to the bound of"
    " the relinearized product (compared exactly); a squaring switches its operand once. A linear operation"
    " never gains capacity from a modulus switch, so this policy fits the longest chains of linear operations;"
    " it keeps values at high levels, which makes the charged work an upper estimate. It is the costing policy"
    " of the harness, not a schedule a consumer has adopted."
)


class TapeMachine:
    """The shape run of the V1 register machine: (bound, level) pairs and the ledger."""

    def __init__(self, p: Profile):
        self.p = p
        top = p.top
        self.input = self._admit(p.fresh_noise(), top)
        trivial = self._admit(p.plaintext_noise(), top)
        self.registers = [trivial] * REGISTERS
        self.lanes = [trivial] * STATE_LANES
        self.output = None
        self.outputs = 0
        self.current = [0] * 5
        self.total = [0] * 5
        self.by_opcode = [[0] * 5 for _ in range(12)]
        self.instructions = [0] * 11
        self.costliest = [[0] * 5 for _ in range(11)]
        self.peak_persistent = self._persistent()
        self.peak_working = self.peak_persistent

    # Shape rules (crates/iroha_fhe/src/bgv/plan.rs) ------------------------

    def _admit(self, bound: int, level: int) -> tuple:
        if bound > self.p.capacity(level):
            raise NoiseBudgetExceeded(f"level {level}: {bound.bit_length()} bits")
        return (bound, level)

    def _add(self, lhs: tuple, rhs: tuple) -> tuple:
        assert lhs[1] == rhs[1]
        return self._admit(lhs[0] + rhs[0], lhs[1])

    def _add_scalar(self, value: tuple) -> tuple:
        return self._admit(value[0] + self.p.constant_l1(), value[1])

    def _mul_plain(self, value: tuple, l1: int) -> tuple:
        result = self._admit(value[0] * l1, value[1])
        self.current[PM] += 1
        self.current[UNITS] += self.p.plaintext_multiplication_units(value[1])
        return result

    def _multiply_shape(self, lhs: tuple, rhs: tuple) -> tuple:
        level = lhs[1]
        tensor = self._admit(self.p.degree * lhs[0] * rhs[0], level)
        return self._admit(tensor[0] + self.p.key_switch_noise(level), level)

    def _switch_down_shape(self, value: tuple) -> tuple:
        if value[1] == 0:
            raise NoiseBudgetExceeded("no level left")
        return self._admit(self.p.switch_down_noise(value[0], value[1]), value[1] - 1)

    def _lower_multiplication(self, lhs: tuple, rhs: tuple) -> bool:
        """Whether multiplying one level lower leaves more room (plan_lower_multiplication)."""
        level = lhs[1]
        if level == 0:
            return False
        try:
            lower_lhs = self._switch_down_shape(lhs)
            lower_rhs = self._switch_down_shape(rhs)
        except NoiseBudgetExceeded:
            return False
        # Unadmitted product bounds: either may exceed the capacity of its level.
        product = self.p.degree * lhs[0] * rhs[0] + self.p.key_switch_noise(level)
        lower_product = self.p.degree * lower_lhs[0] * lower_rhs[0] + self.p.key_switch_noise(level - 1)
        return self.p.capacity(level - 1) * product > self.p.capacity(level) * lower_product

    # Machine ----------------------------------------------------------------

    def _persistent(self) -> int:
        values = [self.input] + self.registers + self.lanes + ([self.output] if self.output is not None else [])
        return sum(self.p.residue_bytes(level) for _, level in values)

    def _working(self, temporaries: list, scratch: int) -> None:
        total = self._persistent() + scratch + sum(self.p.residue_bytes(level) for _, level in temporaries)
        self.peak_working = max(self.peak_working, total)

    def _switch_down(self, value: tuple) -> tuple:
        lower = self._switch_down_shape(value)
        self.current[MS] += 1
        self.current[UNITS] += self.p.switch_down_units(value[1])
        return lower

    def _switch_to(self, value: tuple, level: int) -> tuple:
        while value[1] > level:
            value = self._switch_down(value)
        return value

    def _align(self, lhs: tuple, rhs: tuple) -> tuple:
        level = min(lhs[1], rhs[1])
        return self._switch_to(lhs, level), self._switch_to(rhs, level)

    def _lowered_product(self, lhs: tuple, rhs: tuple, same: bool) -> tuple:
        if same:
            rhs = lhs
        else:
            lhs, rhs = self._align(lhs, rhs)
        while self._lower_multiplication(lhs, rhs):
            lhs = self._switch_down(lhs)
            rhs = lhs if same else self._switch_down(rhs)
        level = lhs[1]
        scratch = self.p.residue_bytes(level, 3) + self.p.key_switch_scratch_bytes(level)
        self._working([lhs] if same else [lhs, rhs], scratch)
        product = self._multiply_shape(lhs, rhs)
        self.current[CM] += 1
        self.current[KS] += 1
        self.current[UNITS] += self.p.multiplication_units(level)
        return product

    def _load_input(self) -> tuple:
        level = self.input[1]
        current = self._mul_plain(self.input, self.p.mask_l1())
        scratch = self.p.key_switch_scratch_bytes(level)
        for _ in range(self.p.broadcast_steps()):
            image = self._admit(current[0] + self.p.key_switch_noise(level), level)
            self.current[KS] += 1
            self.current[UNITS] += self.p.key_switch_units(level)
            self._working([current, image], scratch)
            current = self._add(current, image)
        return current

    def select(self, cond: tuple, zero: tuple, nonzero: tuple) -> tuple:
        powered = cond
        for _ in range(SELECT_SQUARINGS):
            powered = self._lowered_product(powered, powered, True)
        one = self._admit(self.p.plaintext_noise(), powered[1])
        powered = self._lowered_product(powered, one, False)
        indicator = self._add_scalar(powered)
        zero, nonzero = self._align(zero, nonzero)
        delta = self._add(zero, nonzero)
        self._working([indicator, delta, zero, nonzero], 0)
        product = self._lowered_product(indicator, delta, False)
        nonzero, product = self._align(nonzero, product)
        return self._add(nonzero, product)

    def step(self, instruction: tuple) -> None:
        self.current = [0] * 5
        tag = instruction[0]
        registers = self.registers
        if tag == LOAD_INPUT:
            registers[instruction[1]] = self._load_input()
        elif tag == LOAD_STATE:
            registers[instruction[1]] = self.lanes[instruction[2]]
        elif tag == STORE_STATE:
            self.lanes[instruction[1]] = registers[instruction[2]]
        elif tag == LOAD_CONST:
            registers[instruction[1]] = self._admit(self.p.plaintext_noise(), self.p.top)
        elif tag == ADD:
            lhs, rhs = self._align(registers[instruction[2]], registers[instruction[3]])
            self._working([lhs, rhs], 0)
            registers[instruction[1]] = self._add(lhs, rhs)
        elif tag in (ADD_PLAIN, SUB_PLAIN):
            registers[instruction[1]] = self._add_scalar(registers[instruction[2]])
        elif tag == MUL_PLAIN:
            registers[instruction[1]] = self._mul_plain(registers[instruction[2]], self.p.constant_l1())
        elif tag == MUL:
            lhs, rhs = instruction[2], instruction[3]
            registers[instruction[1]] = self._lowered_product(registers[lhs], registers[rhs], lhs == rhs)
        elif tag == SELECT_EQ_ZERO:
            registers[instruction[1]] = self.select(
                registers[instruction[2]], registers[instruction[3]], registers[instruction[4]]
            )
        elif tag == OUTPUT:
            term = self._mul_plain(registers[instruction[1]], self.p.mask_l1())
            accumulator, self.output = self.output, None
            if accumulator is None:
                self.output = term
            else:
                accumulator, term = self._align(accumulator, term)
                self._working([accumulator, term], 0)
                self.output = self._add(accumulator, term)
            self.outputs += 1
        else:
            raise ValueError(f"unknown opcode tag {tag}")
        work = self.current
        for index in range(5):
            self.total[index] += work[index]
            self.by_opcode[tag][index] += work[index]
        self.instructions[tag] += 1
        if work[UNITS] >= self.costliest[tag][UNITS]:
            self.costliest[tag] = list(work)
        persistent = self._persistent()
        self.peak_persistent = max(self.peak_persistent, persistent)
        self.peak_working = max(self.peak_working, persistent)

    def finish(self) -> tuple:
        if self.output is None:
            raise ValueError("the tape emitted no output")
        accumulator, self.output = self.output, None
        self.current = [0] * 5
        packed = self._mul_plain(accumulator, self.p.vector_l1())
        for index in range(5):
            self.total[index] += self.current[index]
            self.by_opcode[FINAL_MASK][index] += self.current[index]
        return packed


# TODO(R.11): replace the flooding projection by the selected circuit-privacy construction
# and its proved parameters; H and kappa below are illustrative.
def flooded_bound(p: Profile, bound: int, log2_releases: int, kappa: int) -> int:
    """Bound after the projected flooding sanitization (see `flooded_bound` of the harness).

    With E = ceil(V / t) bounding the error and F = H * N * E * 2^kappa the
    half-width of the flood, the flooded and re-randomized ciphertext has the
    bound V + t*F + V_fresh. A projection of one published technique with
    unselected parameters; it is not a sanitization construction.
    """
    error = -(-bound // p.t)
    flood = (error * p.degree) << (log2_releases + kappa)
    return bound + flood * p.t + p.fresh_noise()


def plan_tape(p: Profile, tape: tuple, sanitization: Optional[tuple] = None) -> dict:
    """Run `tape` over public shapes; with `sanitization` the output must also hold the flood."""
    try:
        machine = TapeMachine(p)
    except NoiseBudgetExceeded:
        return {"fits": False, "instruction": 0, "tag": tape[0][0] if tape else FINAL_MASK}
    for index, instruction in enumerate(tape):
        try:
            machine.step(instruction)
        except NoiseBudgetExceeded:
            return {"fits": False, "instruction": index, "tag": instruction[0]}
    try:
        packed = machine.finish()
    except NoiseBudgetExceeded:
        return {"fits": False, "instruction": len(tape), "tag": FINAL_MASK}
    plan = {
        "fits": True,
        "level": packed[1],
        "bound": packed[0],
        "capacity": p.capacity(packed[1]),
        "total": list(machine.total),
        "by_opcode": [list(work) for work in machine.by_opcode],
        "instructions": list(machine.instructions),
        "costliest": [list(work) for work in machine.costliest],
        "peak_persistent_bytes": machine.peak_persistent,
        "peak_working_bytes": machine.peak_working,
    }
    if sanitization is not None:
        flooded = flooded_bound(p, packed[0], *sanitization)
        plan["flooded_bound"] = flooded
        plan["fits"] = flooded <= plan["capacity"]
    return plan


# Maximum-shape tape families (mirror of `families` in the harness) -----------

SCALE = 128


def _frontier(rank: int, scales: int, outputs: int) -> tuple:
    return (
        ((LOAD_INPUT, 0, 0),)
        + ((MUL, 0, 0, 0),) * rank
        + ((MUL_PLAIN, 0, 0, SCALE),) * scales
        + ((OUTPUT, 0),) * outputs
    )


def _affine_loads() -> tuple:
    loads = MAX_INSTRUCTIONS - 1
    return tuple((LOAD_INPUT, index % 4, index % 64) for index in range(loads)) + ((OUTPUT, (loads - 1) % 4),)


def _affine_state_and_registers() -> tuple:
    tape = [(LOAD_INPUT, register, register) for register in range(4)]
    tape += [(STORE_STATE, lane, lane % 4) for lane in range(32)]
    for round_index in range(26):
        tape += [
            (LOAD_STATE, 0, round_index % 32),
            (ADD_PLAIN, 0, 0, 5),
            (SUB_PLAIN, 0, 0, 3),
            (ADD, 1, 0, 1),
            (LOAD_CONST, 2, 7),
            (ADD, 3, 2, 3),
        ]
    tape += [(OUTPUT, index % 4) for index in range(MAX_OUTPUTS)]
    return tuple(tape)


def _bounded_selects() -> tuple:
    return ((SELECT_EQ_ZERO, 0, 1, 2, 3),) * (MAX_INSTRUCTIONS - 1) + ((OUTPUT, 0),)


def _bounded_scaled_rank_chain() -> tuple:
    return (
        ((LOAD_INPUT, 0, 0),)
        + ((MUL_PLAIN, 0, 0, SCALE),) * (MAX_INSTRUCTIONS - 2 - BOUNDED_MAX_RANK)
        + ((MUL, 0, 0, 0),) * BOUNDED_MAX_RANK
        + ((OUTPUT, 0),)
    )


def _bounded_alternating_rank_chain() -> tuple:
    scale = (MUL_PLAIN, 0, 0, SCALE)
    return (
        ((LOAD_INPUT, 0, 0),)
        + (scale, (MUL, 0, 0, 0)) * BOUNDED_MAX_RANK
        + (scale,)
        + ((OUTPUT, 0),) * MAX_OUTPUTS
    )


def _bounded_select_then_products() -> tuple:
    return (
        ((LOAD_INPUT, 0, 5), (LOAD_INPUT, 1, 9), (LOAD_CONST, 2, 77), (SELECT_EQ_ZERO, 3, 0, 1, 2))
        + ((MUL, 3, 3, 3),) * (BOUNDED_MAX_RANK - SELECT_MULTIPLICATIONS)
        + ((OUTPUT, 3),) * MAX_OUTPUTS
    )


# name -> (class, description, tape)
FAMILIES = {
    "affine.loads": (
        "affine.v1",
        "255 input loads and one output: the key-switch extreme",
        _affine_loads(),
    ),
    "affine.scale_chain": (
        "affine.v1",
        "one load, 254 sequential constant multiplications and one output: the noise extreme without"
        " ciphertext multiplication",
        _frontier(0, MAX_INSTRUCTIONS - 2, 1),
    ),
    "affine.scale_then_outputs": (
        "affine.v1",
        "one load, 191 sequential constant multiplications and 64 outputs",
        _frontier(0, MAX_INSTRUCTIONS - 1 - MAX_OUTPUTS, MAX_OUTPUTS),
    ),
    "affine.state_and_registers": (
        "affine.v1",
        "every affine opcode, every register and every state lane holding an encrypted value, 64 outputs:"
        " the live-buffer extreme",
        _affine_state_and_registers(),
    ),
    "bounded.selects": (
        "bounded.v1",
        "255 independent selects and one output: 2,550 ciphertext multiplications",
        _bounded_selects(),
    ),
    "bounded.scaled_rank_chain": (
        "bounded.v1",
        "one load, 238 sequential constant multiplications, 16 sequential squarings and one output: the"
        " noise extreme at rank 16",
        _bounded_scaled_rank_chain(),
    ),
    "bounded.rank_chain_outputs": (
        "bounded.v1",
        "one load, 16 sequential squarings and 64 outputs",
        _frontier(BOUNDED_MAX_RANK, 0, MAX_OUTPUTS),
    ),
    "bounded.alternating_rank_chain": (
        "bounded.v1",
        "one load, sixteen rounds of one constant multiplication and one squaring, one more constant"
        " multiplication and 64 outputs",
        _bounded_alternating_rank_chain(),
    ),
    "bounded.select_then_products": (
        "bounded.v1",
        "two loads and a constant, one select on the loaded condition, six squarings and 64 outputs",
        _bounded_select_then_products(),
    ),
}

# One instruction of every opcode on operands loaded at the top level.
INSTRUCTION_PROFILE_AFFINE = (
    (LOAD_INPUT, 0, 5),
    (LOAD_INPUT, 1, 9),
    (LOAD_STATE, 2, 0),
    (STORE_STATE, 1, 0),
    (LOAD_CONST, 3, 77),
    (ADD, 2, 0, 1),
    (ADD_PLAIN, 2, 2, 5),
    (SUB_PLAIN, 2, 2, 3),
    (MUL_PLAIN, 2, 2, SCALE),
    (OUTPUT, 3),
    (OUTPUT, 2),
)
INSTRUCTION_PROFILE_BOUNDED = INSTRUCTION_PROFILE_AFFINE[:9] + (
    (MUL, 2, 0, 1),
    (SELECT_EQ_ZERO, 3, 0, 1, 3),
    (OUTPUT, 3),
    (OUTPUT, 2),
)


def peak_rank(tape: tuple) -> int:
    """The largest logical rank a tape reaches, by the rank rules of the V1 descriptor."""
    registers = [0] * REGISTERS
    state = [0] * STATE_LANES
    peak = 0
    for instruction in tape:
        tag = instruction[0]
        if tag in (LOAD_INPUT, LOAD_CONST):
            registers[instruction[1]] = 0
        elif tag == LOAD_STATE:
            registers[instruction[1]] = state[instruction[2]]
        elif tag == STORE_STATE:
            state[instruction[1]] = registers[instruction[2]]
        elif tag == ADD:
            registers[instruction[1]] = max(registers[instruction[2]], registers[instruction[3]])
        elif tag in (ADD_PLAIN, SUB_PLAIN, MUL_PLAIN):
            registers[instruction[1]] = registers[instruction[2]]
        elif tag == MUL:
            registers[instruction[1]] = max(registers[instruction[2]], registers[instruction[3]]) + 1
        elif tag == SELECT_EQ_ZERO:
            registers[instruction[1]] = max(
                registers[instruction[2]] + SELECT_MULTIPLICATIONS,
                registers[instruction[3]] + SELECT_BRANCH_RANK,
                registers[instruction[4]] + SELECT_BRANCH_RANK,
            )
        peak = max(peak, max(registers))
    return peak


_TAPE_PLAN_CACHE: dict = {}


def cached_plan(shape: tuple, tape: tuple, sanitization: Optional[tuple] = None) -> dict:
    """`plan_tape` on the profile of `shape`, memoized for the lifetime of the process."""
    key = (shape, tape, sanitization)
    if key not in _TAPE_PLAN_CACHE:
        _TAPE_PLAN_CACHE[key] = plan_tape(profile("plan", shape), tape, sanitization)
    return _TAPE_PLAN_CACHE[key]


def with_main_primes(shape: tuple, count: int) -> tuple:
    log_degree, t, (bits, _), special, digit_primes = shape
    return (log_degree, t, (bits, count), special, digit_primes)


def largest_main_primes(shape: tuple) -> int:
    """Main primes a basis of the implementation can hold beside the special primes of `shape`."""
    return MAX_BASIS_PRIMES - shape[3][1]


def tape_minimal_main_primes(shape: tuple, tape: tuple, sanitization: Optional[tuple] = None) -> Optional[int]:
    """Fewest main primes of the size of `shape` on which the tape fits; None above the basis limit.

    Bisection: a longer chain of the same primes admits whatever a shorter one
    admits. The result is confirmed to fit and its predecessor not to.
    """
    low, high = 1, largest_main_primes(shape)
    if not cached_plan(with_main_primes(shape, high), tape, sanitization)["fits"]:
        return None
    while low < high:
        middle = (low + high) // 2
        if cached_plan(with_main_primes(shape, middle), tape, sanitization)["fits"]:
            high = middle
        else:
            low = middle + 1
    assert cached_plan(with_main_primes(shape, low), tape, sanitization)["fits"]
    assert low == 1 or not cached_plan(with_main_primes(shape, low - 1), tape, sanitization)["fits"]
    return low


def frontier_scales(shape: tuple, rank: int) -> int:
    """Most sequential constant multiplications that fit after one load and `rank` squarings, before 64 outputs."""
    limit = MAX_INSTRUCTIONS - 1 - rank - MAX_OUTPUTS
    fits = lambda scales: cached_plan(shape, _frontier(rank, scales, MAX_OUTPUTS))["fits"]  # noqa: E731
    if not fits(0):
        return -1
    low, high = 0, limit
    while low < high:
        middle = (low + high + 1) // 2
        if fits(middle):
            low = middle
        else:
            high = middle - 1
    return low


# ---------------------------------------------------------------------------
# Core-SVP sanity calculation (not a substitute for the Lattice Estimator)
# ---------------------------------------------------------------------------

SIGMA_ERROR = math.sqrt(ERROR_ETA / 2)
SIGMA_SECRET = math.sqrt(2 / 3)


def _log2_delta(beta: int) -> float:
    return math.log2((math.pi * beta) ** (1 / beta) * beta / (2 * math.pi * math.e)) / (2 * (beta - 1))


def core_svp_block_size(degree: int, log2_modulus: float) -> int:
    """Smallest BKZ block size at which the primal uSVP attack succeeds (2016 estimate).

    The lattice has dimension d = m + n + 1 for m <= n samples and volume
    q^m * (sigma_e / sigma_s)^n after rescaling the ternary secret. The attack
    succeeds when sigma_e * sqrt(beta) <= delta^(2*beta - d - 1) * vol^(1/d).
    """
    scaling = math.log2(SIGMA_ERROR / SIGMA_SECRET)

    def succeeds(beta: int) -> bool:
        log_delta = _log2_delta(beta)
        lhs = math.log2(SIGMA_ERROR) + 0.5 * math.log2(beta)
        # The optimal number of samples is found by scanning a coarse grid.
        for samples in range(max(1, degree // 16), degree + 1, max(1, degree // 256)):
            dimension = samples + degree + 1
            log_volume = samples * log2_modulus + degree * scaling
            if lhs <= (2 * beta - dimension - 1) * log_delta + log_volume / dimension:
                return True
        return False

    low, high = 50, degree
    if not succeeds(high):
        return high
    while low < high:
        middle = (low + high) // 2
        if succeeds(middle):
            high = middle
        else:
            low = middle + 1
    return low


def security_sanity(p: Profile) -> dict:
    log2_modulus = p.total_modulus_bits()
    beta = core_svp_block_size(p.degree, log2_modulus)
    # d <= 2n + 1; the polynomial factor of the BDGL16 model is taken at that dimension.
    dimension = 2 * p.degree + 1
    return {
        "lwe_dimension": number(p.degree, "count", "parameter"),
        "log2_largest_modulus": number(round(log2_modulus, 2), "bits", "projection"),
        "bkz_block_size": number(beta, "count", "projection"),
        "core_svp_classical_bits": number(round(0.292 * beta, 1), "bits", "projection"),
        "core_svp_quantum_bits": number(round(0.265 * beta, 1), "bits", "projection"),
        "bdgl16_style_classical_bits": number(
            round(0.292 * beta + 16.4 + math.log2(8 * dimension), 1), "bits", "projection"
        ),
    }


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------


def number(value, unit: str, cls: str, **extra) -> dict:
    assert cls in CLASSES
    out = {"value": value, "unit": unit, "class": cls}
    out.update(extra)
    return out


def measured(value, unit: str, **extra) -> dict:
    return number(value, unit, "measured", **extra)


def projection(value, unit: str, **extra) -> dict:
    return number(value, unit, "projection", **extra)


# ---------------------------------------------------------------------------
# Lattice Estimator record (scripts/fhe_bgv_lattice_estimator.sage)
# ---------------------------------------------------------------------------

ESTIMATOR_MODELS = ("BDGL16", "ADPS16", "ADPS16-quantum")
ESTIMATOR_CLASSICAL_MODELS = ("BDGL16", "ADPS16")
ESTIMATOR_MODEL_FREE = "none"
ESTIMATOR_INSTANCES = ("Q:n", "QP:n", "QP:oo")
ESTIMATOR_LATTICE_ATTACKS = ("usvp", "bdd", "bdd_hybrid", "bdd_mitm_hybrid", "dual", "dual_hybrid")
ESTIMATOR_MODEL_FREE_ATTACKS = ("arora-gb", "bkw")
ESTIMATOR_ATTACK_NAMES = {
    "usvp": "primal uSVP",
    "bdd": "primal BDD",
    "bdd_hybrid": "primal hybrid",
    "bdd_mitm_hybrid": "primal hybrid with meet in the middle",
    "dual": "dual",
    "dual_hybrid": "dual hybrid",
    "arora-gb": "Arora-GB with guessing",
    "bkw": "coded BKW",
}
# The design target of task C.3: classical bits under the reduction cost model its design memo names.
DESIGN_TARGET_BITS = 128
DESIGN_TARGET_MODEL = "BDGL16"
_PROPOSAL_NAME = re.compile(r"^bgv\.derive\.n(\d+)\.t(\d+)\.q(\d+)x(\d+)\.p(\d+)x(\d+)$")


def estimated_profiles() -> dict:
    """Name -> (shape, role) of every profile the estimator record has to cover."""
    out = {name: (shape, f"candidate for {CANDIDATE_CLASS[name]}") for name, shape in CANDIDATES.items()}
    for config, (name, shape) in MEASURED_CONFIGS.items():
        slots = profile(name, shape).slots()
        kind = "batching comparator" if slots == 1 << shape[0] else "timing configuration"
        out.setdefault(name, (shape, f"measured {kind}; not a candidate"))
    return out


def proposal_shape(name: str) -> Optional[tuple]:
    """The shape a name of the estimator's `--shape` option states, or None."""
    match = _PROPOSAL_NAME.match(name)
    if match is None:
        return None
    log_degree, t, main_count, main_bits, special_count, special_bits = (int(item) for item in match.groups())
    return (log_degree, t, (main_bits, main_count), (special_bits, special_count), 2)


def estimator_script_facts(root: Path) -> dict:
    """The pinned commit of the estimator script and the hash of its code (the file below its header)."""
    text = (root / ESTIMATOR_SCRIPT).read_text()
    commit = re.search(r'^ESTIMATOR_COMMIT = "([0-9a-f]{40})"$', text, re.M)
    lines = text.splitlines(keepends=True)
    start = next((index for index, line in enumerate(lines) if not line.startswith("#")), len(lines))
    return {
        "commit": commit.group(1) if commit else None,
        "code_sha256": hashlib.sha256("".join(lines[start:]).encode()).hexdigest(),
    }


def read_estimator_record(text: str) -> dict:
    """The JSON lines of an estimator output record, by kind, in file order.

    `invocations` pairs each RUN line with the END line that follows it, or
    with None when the invocation was cut off before it printed one.
    """
    record: dict = {"RUN": [], "INSTANCE": [], "RESULT": [], "SELFCHECK": [], "END": [], "invocations": []}
    for line in text.splitlines():
        kind, _, body = line.partition(" ")
        if kind not in ("RUN", "INSTANCE", "RESULT", "SELFCHECK", "END"):
            continue
        item = json.loads(body)
        record[kind].append(item)
        if kind == "RUN":
            record["invocations"].append([item, None])
        elif kind == "END" and record["invocations"] and record["invocations"][-1][1] is None:
            record["invocations"][-1][1] = item
    return record


def estimator_results(record: dict) -> dict:
    """(profile, instance, model, attack) -> the RESULT to report: the last finished one, else the last."""
    chosen: dict = {}
    for result in record["RESULT"]:
        key = (result["profile"], result["instance"], result["model"], result["attack"])
        if result["status"] == "ok" or chosen.get(key, {}).get("status") != "ok":
            chosen[key] = result
    return chosen


def estimator_record_problems(root: Path) -> list:
    """Defects of the tracked estimator record against the script that produced it and against this model."""
    path = root / ESTIMATOR_OUTPUT
    if not path.is_file():
        return [f"{ESTIMATOR_OUTPUT} is missing"]
    try:
        record = read_estimator_record(path.read_text())
    except ValueError as error:
        return [f"{ESTIMATOR_OUTPUT}: {error}"]
    problems = []
    facts = estimator_script_facts(root)
    if not record["RUN"]:
        problems.append(f"{ESTIMATOR_OUTPUT}: no RUN line")
    if len(record["END"]) != len(record["RUN"]) or any(end is None for _run, end in record["invocations"]):
        problems.append(f"{ESTIMATOR_OUTPUT}: an invocation has no END line")
    for run in record["RUN"]:
        if facts["commit"] is None or run.get("estimator_commit") != facts["commit"]:
            problems.append(f"{ESTIMATOR_OUTPUT}: a run did not use the commit {ESTIMATOR_SCRIPT} pins")
        if run.get("script_code_sha256") != facts["code_sha256"]:
            problems.append(f"{ESTIMATOR_OUTPUT}: a run was produced by other code than {ESTIMATOR_SCRIPT} now holds")
    checks = [check.get("equal_to_LWE_estimate") for check in record["SELFCHECK"]]
    if not checks or not all(check is True for check in checks):
        problems.append(f"{ESTIMATOR_OUTPUT}: no passing self-check against LWE.estimate")
    profiles = estimated_profiles()
    seen = set()
    for instance in record["INSTANCE"]:
        name = instance.get("profile")
        label = f"{name}/{instance.get('instance')}"
        shape = profiles[name][0] if instance.get("pinned") and name in profiles else None
        if shape is None and not instance.get("pinned"):
            shape = proposal_shape(str(name))
        if shape is None or instance.get("instance") not in ESTIMATOR_INSTANCES:
            problems.append(f"{ESTIMATOR_OUTPUT}: instance {label} is not one this model knows")
            continue
        p = profile(str(name), shape)
        modulus = p.modulus(p.top) * (p.special_product if instance["modulus"] == "QP" else 1)
        if instance.get("q") != str(modulus) or instance.get("n") != p.degree:
            problems.append(f"{ESTIMATOR_OUTPUT}: the modulus or the dimension of {label} differs from this model")
        if instance.get("error") != f"centered binomial, eta = {ERROR_ETA}":
            problems.append(f"{ESTIMATOR_OUTPUT}: the error distribution of {label} differs from this model")
        if instance.get("secret") != "uniform ternary on {-1, 0, 1}":
            problems.append(f"{ESTIMATOR_OUTPUT}: the secret distribution of {label} differs from this model")
        seen.add((name, instance["instance"]))
    for name in profiles:
        for instance in ESTIMATOR_INSTANCES:
            if (name, instance) not in seen:
                problems.append(f"{ESTIMATOR_OUTPUT}: no instance {name}/{instance}")
    models = ESTIMATOR_MODELS + (ESTIMATOR_MODEL_FREE,)
    attacks = ESTIMATOR_LATTICE_ATTACKS + ESTIMATOR_MODEL_FREE_ATTACKS
    for result in record["RESULT"]:
        key = (result.get("profile"), result.get("instance"))
        if key not in seen or result.get("model") not in models or result.get("attack") not in attacks:
            problems.append(f"{ESTIMATOR_OUTPUT}: a RESULT names an unknown instance, cost model or attack")
        elif result.get("status") == "ok" and not (
            result.get("log2_rop") == "oo" or isinstance(result.get("log2_rop"), (int, float))
        ):
            problems.append(f"{ESTIMATOR_OUTPUT}: a finished RESULT has no cost")
    return problems


def estimated(value, unit: str, **extra) -> dict:
    return number(value, unit, "estimator", **extra)


def _attack_entry(result: Optional[dict]) -> dict:
    """One attack on one instance under one cost model, as the summary reports it."""
    if result is None:
        return {
            "status": "not_attempted",
            "reason": "the output record holds no RESULT line for this attack on this instance",
        }
    entry: dict = {"status": result["status"]}
    if result["status"] == "ok":
        infinite = result["log2_rop"] == "oo"
        entry["log2_cost"] = "infinite" if infinite else estimated(result["log2_rop"], "bits")
        for key, label in (("beta", "block_size"), ("d", "lattice_dimension"), ("zeta", "guessed_coordinates")):
            if isinstance(result["cost"].get(key), int):
                entry[label] = estimated(result["cost"][key], "count")
    else:
        # How long the attack ran before it was cut off; the record has the time of every attack.
        entry["reason"] = result["message"]
        entry["seconds"] = estimated(result["seconds"], "seconds")
    return entry


def _finite_cost(entry: dict) -> Optional[float]:
    cost = entry.get("log2_cost")
    return cost["value"] if isinstance(cost, dict) else None


def _instance_block(results: dict, name: str, instance: str, p: Profile) -> dict:
    modulus = p.modulus(p.top) * (p.special_product if instance.startswith("QP") else 1)
    block: dict = {
        "modulus_bits": projection(modulus.bit_length(), "bits"),
        "samples": "n" if instance.endswith(":n") else "unlimited",
        "models": {},
        "attacks_without_a_cost_model": {
            attack: _attack_entry(results.get((name, instance, ESTIMATOR_MODEL_FREE, attack)))
            for attack in ESTIMATOR_MODEL_FREE_ATTACKS
        },
    }
    for model in ESTIMATOR_MODELS:
        attacks = {
            attack: _attack_entry(results.get((name, instance, model, attack)))
            for attack in ESTIMATOR_LATTICE_ATTACKS
        }
        finite = [(cost, attack) for attack, entry in attacks.items() if (cost := _finite_cost(entry)) is not None]
        entry: dict = {"attacks": attacks}
        if finite:
            cost, attack = min(finite)
            entry["minimum"] = {"attack": attack, "log2_cost": estimated(cost, "bits")}
        entry["attacks_without_a_cost"] = [
            f"{attack} ({item['status']})" for attack, item in attacks.items() if item["status"] != "ok"
        ]
        block["models"][model] = entry
    return block


def _verdict_block(instances: dict) -> dict:
    """Per cost model: the cheapest finished attack over every instance, and the design target."""
    out: dict = {}
    for model in ESTIMATOR_MODELS:
        finite = []
        missing = []
        for instance, block in instances.items():
            attacks = dict(block["models"][model]["attacks"])
            attacks.update(block["attacks_without_a_cost_model"])
            for attack, entry in attacks.items():
                cost = _finite_cost(entry)
                if cost is not None:
                    finite.append((cost, instance, attack))
                elif entry["status"] != "ok":
                    missing.append(f"{instance} {attack} ({entry['status']})")
        verdict: dict = {"attacks_without_a_cost": missing}
        if finite:
            cost, instance, attack = min(finite)
            verdict.update(
                {
                    "minimum_log2_cost": estimated(cost, "bits"),
                    "minimum_instance": instance,
                    "minimum_attack": attack,
                }
            )
            if model in ESTIMATOR_CLASSICAL_MODELS:
                verdict["meets_design_target_on_the_attacks_with_a_cost"] = cost >= DESIGN_TARGET_BITS
                verdict["margin_bits"] = estimated(round(cost - DESIGN_TARGET_BITS, 4), "bits")
        out[model] = verdict
    return out


def _sanity_comparison(p: Profile, instances: dict) -> dict:
    """The core-SVP sanity numbers of this script beside the estimator's primal uSVP on Q*P with m = n."""
    sanity = security_sanity(p)
    out: dict = {"instance": "QP:n", "attack": "usvp"}
    largest = 0.0
    for label, model, key in (
        ("core_svp_classical", "ADPS16", "core_svp_classical_bits"),
        ("core_svp_quantum", "ADPS16-quantum", "core_svp_quantum_bits"),
        ("bdgl16_style_classical", "BDGL16", "bdgl16_style_classical_bits"),
    ):
        entry = instances["QP:n"]["models"][model]["attacks"]["usvp"]
        cost = _finite_cost(entry)
        if cost is None:
            continue
        difference = round(cost - sanity[key]["value"], 4)
        largest = max(largest, abs(difference))
        out[label] = {
            "sanity_bits": sanity[key],
            "estimator_bits": estimated(cost, "bits"),
            "estimator_minus_sanity_bits": estimated(difference, "bits"),
        }
        if model == "ADPS16" and "block_size" in entry:
            out["block_size"] = {
                "sanity": sanity["bkz_block_size"],
                "estimator": entry["block_size"],
            }
    out["largest_difference_bits"] = estimated(round(largest, 4), "bits")
    out["agrees_within_one_bit"] = largest <= 1.0
    return out


def _estimated_profile_block(results: dict, name: str, shape: tuple) -> dict:
    p = profile(name, shape)
    instances = {instance: _instance_block(results, name, instance, p) for instance in ESTIMATOR_INSTANCES}
    keys = p.digit_count() * (1 + p.broadcast_steps())
    return {
        "lwe_dimension": number(p.degree, "count", "parameter"),
        "published_samples": {
            "public_key_modulo_Q": projection(p.degree, "count"),
            "one_fresh_ciphertext_modulo_Q_under_its_own_mask": projection(2 * p.degree, "count"),
            "relinearization_and_broadcast_galois_keys_modulo_QP": projection(keys * p.degree, "count"),
        },
        "instances": instances,
        "verdict": _verdict_block(instances),
        "core_svp_sanity_comparison": _sanity_comparison(p, instances),
    }


def _variation_of(shape: tuple) -> Optional[tuple]:
    """(candidate, kind) when `shape` differs from a candidate in its chain length or its ring degree only.

    A chain that lies between two candidates of one ring degree is a shorter
    chain of the longer one.
    """
    chains = []
    for name, candidate in CANDIDATES.items():
        if shape[1:] == candidate[1:] and shape[0] != candidate[0]:
            return name, "ring_degree"
        same_but_count = (
            shape[0] == candidate[0]
            and shape[1] == candidate[1]
            and shape[2][0] == candidate[2][0]
            and shape[3:] == candidate[3:]
        )
        if same_but_count and shape[2][1] != candidate[2][1]:
            chains.append((candidate[2][1], name))
    longer = sorted(item for item in chains if item[0] > shape[2][1])
    if longer:
        return longer[0][1], "main_primes"
    if chains:
        return max(chains)[1], "main_primes"
    return None


def _proposals_block(results: dict, profiles: dict) -> dict:
    """Shapes outside the pinned list that the record estimates, and what they say about each candidate."""
    names = sorted({key[0] for key in results} - set(estimated_profiles()))
    shapes = {}
    for name in names:
        shape = proposal_shape(name)
        if shape is None:
            continue
        block = _estimated_profile_block(results, name, shape)
        block["shape"] = {key: number(value, "count", "parameter") for key, value in profile(name, shape).shape().items()}
        variation = _variation_of(shape)
        if variation is not None:
            block["varies"] = {"candidate": variation[0], "in": variation[1]}
        shapes[name] = block
    by_candidate: dict = {}
    for name, shape in CANDIDATES.items():
        shortfalls = {}
        for model in ESTIMATOR_CLASSICAL_MODELS:
            verdict = profiles[name]["verdict"][model]
            if verdict.get("meets_design_target_on_the_attacks_with_a_cost") is not False:
                continue
            entry: dict = {"shortfall_bits": estimated(round(-verdict["margin_bits"]["value"], 4), "bits")}
            # Chain lengths at the same ring degree, shorter than the candidate's, by what the record says.
            meets = {}
            for other, block in shapes.items():
                other_shape = proposal_shape(other)
                if block.get("varies") == {"candidate": name, "in": "main_primes"} and other_shape is not None:
                    meets[other_shape[2][1]] = block["verdict"][model].get(
                        "meets_design_target_on_the_attacks_with_a_cost"
                    )
            meets[shape[2][1]] = False
            passing = [count for count, verdict_ in meets.items() if verdict_ is True]
            if passing:
                best = max(passing)
                entry["longest_chain_meeting_the_target_at_the_same_ring_degree"] = {
                    "main_primes": estimated(best, "count"),
                    "shape": next(
                        other
                        for other in shapes
                        if proposal_shape(other)[0] == shape[0] and proposal_shape(other)[2][1] == best
                        and shapes[other].get("varies") == {"candidate": name, "in": "main_primes"}
                    ),
                    "the_next_longer_chain_is_recorded_and_fails": meets.get(best + 1) is False,
                }
            larger = [
                other
                for other, block in shapes.items()
                if block.get("varies") == {"candidate": name, "in": "ring_degree"}
                and block["verdict"][model].get("meets_design_target_on_the_attacks_with_a_cost") is True
            ]
            if larger:
                entry["same_chain_at_a_larger_ring_degree_meeting_the_target"] = sorted(
                    larger, key=lambda other: proposal_shape(other)[0]
                )[0]
            shortfalls[model] = entry
        by_candidate[name] = shortfalls
    return {
        "status": (
            "Proposals for the task C.3 owner, not changes: no pinned parameter set was altered. A shape here"
            " is estimated under the same assumptions as the candidates and is as unqualified as they are."
        ),
        "shapes": shapes,
        "shortfalls_and_smallest_changes": by_candidate,
    }


def estimator_block(root: Path) -> dict:
    """`security_estimate.lattice_estimator`: the tracked output record of the estimator script, restated."""
    path = root / ESTIMATOR_OUTPUT
    if not path.is_file():
        return {"status": "not_run", "reason": f"{ESTIMATOR_OUTPUT} is missing", "script": ESTIMATOR_SCRIPT}
    raw = path.read_bytes()
    record = read_estimator_record(raw.decode("utf-8"))
    results = estimator_results(record)
    profiles = {
        name: dict(_estimated_profile_block(results, name, shape), role=role)
        for name, (shape, role) in estimated_profiles().items()
    }
    invocations = []
    for run, end in record["invocations"]:
        end = end or {}
        invocation = {
            "command": run["command"],
            "started_utc": run["started_utc"],
            "finished_utc": end.get("finished_utc", "unknown"),
            "limit_seconds_per_attack": number(run["timeout_seconds"], "seconds", "parameter"),
            "limit_resident_gib_per_attack": number(run["memory_limit_gib"], "gibibytes", "parameter"),
            "attacks_at_once": number(run["parallel"], "count", "parameter"),
            "results_by_status": {
                status: estimated(count, "count") for status, count in sorted(end.get("by_status", {}).items())
            },
        }
        if "wall_seconds" in end:
            invocation["wall_seconds"] = estimated(end["wall_seconds"], "seconds")
        invocations.append(invocation)
    first = record["RUN"][0] if record["RUN"] else {}
    host = first.get("host", {})
    return {
        "status": "run",
        "script": ESTIMATOR_SCRIPT,
        "output_record": ESTIMATOR_OUTPUT,
        "output_record_sha256": hashlib.sha256(raw).hexdigest(),
        "provenance": (
            "Every number of class estimator is copied from a RESULT, RUN or END line of the output record,"
            " or is a minimum, a count or a difference of such values. The record is the raw output of the"
            " script; `--check` holds this block to it and holds the record to the code of the script."
        ),
        "estimator_commit": first.get("estimator_commit", "unknown"),
        "sagemath": first.get("sagemath", "unknown"),
        "python": first.get("python", "unknown"),
        "host": {key: str(host.get(key, "unknown")) for key in ("model", "cpu", "machine", "system", "release")},
        "invocations": invocations,
        "self_check": (
            "equal to LWE.estimate on Kyber512 for every attack and cost model"
            if record["SELFCHECK"] and all(check.get("equal_to_LWE_estimate") is True for check in record["SELFCHECK"])
            else "missing or failed"
        ),
        "what_is_estimated": {
            "problem": "plain LWE of dimension n = N with the exact modulus of the profile; the ring structure is ignored",
            "secret": "uniform ternary on {-1, 0, 1}",
            "error": f"centered binomial, eta = {ERROR_ETA}: the error e of a sample b = -a*s + t*e after multiplying by 1/t",
            "instances": {
                "Q:n": "modulus Q, m = n samples: the public key",
                "QP:n": "modulus Q*P, m = n samples: one switching-key polynomial",
                "QP:oo": "modulus Q*P, unlimited samples: the conservative instance for every exposure of the secret key",
            },
            "attacks": dict(ESTIMATOR_ATTACK_NAMES),
            "cost_models": {
                "BDGL16": "classical sieving, 0.292*beta + 16.4 + log2(8*d) per reduction",
                "ADPS16": "classical core-SVP, 0.292*beta",
                "ADPS16-quantum": "quantum core-SVP, 0.265*beta",
            },
        },
        "design_target": {
            "classical_bits": number(DESIGN_TARGET_BITS, "bits", "parameter"),
            "cost_model": DESIGN_TARGET_MODEL,
            "source": (
                "the task C.3 design memo: at least 128 classical bits under BDGL16 reduction costs, quantum"
                " costs reported separately; the verdict under ADPS16 (core-SVP) is reported beside it"
            ),
        },
        "not_covered": [
            "the ring structure: the estimate is for plain LWE of the same dimension",
            "the circular-security (key-dependent message) assumption of publishing encryptions of s^2 and"
            " s(X^k) under s",
            "keys or ciphertexts that were not sampled honestly, and any malformed key",
            "side channels of the implementation",
            "the class fit: no candidate holds the maximum shape of its class under instruction-by-instruction"
            " lowering, and an estimate does not change that",
            "review: the numbers are the output of one tool under its heuristics; nobody has reviewed the"
            " parameters, and no profile is qualified",
        ],
        "profiles": profiles,
        "proposals": _proposals_block(results, profiles),
    }


def profile_block(p: Profile, galois_keys: int) -> dict:
    top = p.top
    return {
        "shape": {key: number(value, "count", "parameter") for key, value in p.shape().items()},
        "first_main_prime": number(p.main[0], "count", "parameter"),
        "last_main_prime": number(p.main[-1], "count", "parameter"),
        "special_primes": [number(prime, "count", "parameter") for prime in p.special],
        "modulus_bits": projection(p.modulus(top).bit_length(), "bits"),
        "special_modulus_bits": projection(p.special_product.bit_length(), "bits"),
        "key_switch_digits": projection(p.digit_count(), "count"),
        "scalar_slots": projection(p.slots(), "count"),
        "slot_mask_l1_norm": projection(p.mask_l1(), "count"),
        "broadcast_key_switches": projection(p.broadcast_steps(), "count"),
        "fresh_noise_bound_bits": projection(p.fresh_noise().bit_length(), "bits"),
        "key_switch_noise_bound_bits": projection(p.key_switch_noise(top).bit_length(), "bits"),
        "sizes": {
            "ciphertext_frame_bytes_top_level": projection(p.ciphertext_bytes(top), "bytes"),
            "ciphertext_frame_bytes_lowest_level": projection(p.ciphertext_bytes(0), "bytes"),
            "public_key_frame_bytes": projection(p.public_key_bytes(), "bytes"),
            "secret_key_custody_frame_bytes": projection(p.secret_key_bytes(), "bytes"),
            "switching_key_frame_bytes": projection(p.switching_key_bytes(), "bytes"),
            "galois_keys_for_broadcast": projection(galois_keys, "count"),
            "evaluation_keys_frame_bytes": projection(p.evaluation_key_bytes(galois_keys), "bytes"),
            "key_switch_scratch_bytes_top_level": projection(p.key_switch_scratch_bytes(top), "bytes"),
        },
        "work_units_top_level": {
            "multiplication_with_relinearization": projection(p.multiplication_units(top), "work_units"),
            "tensor": projection(p.tensor_units(top), "work_units"),
            "key_switch": projection(p.key_switch_units(top), "work_units"),
            "plaintext_multiplication": projection(p.plaintext_multiplication_units(top), "work_units"),
            "modulus_switch": projection(p.switch_down_units(top), "work_units"),
            "encryption": projection(p.encryption_units(), "work_units"),
            "decryption": projection(p.decryption_units(top), "work_units"),
        },
        "security_sanity": security_sanity(p),
    }


def plan_block(plan: Plan) -> dict:
    return {
        "steps": [
            {
                "step": step["step"],
                "level": projection(step["level"], "count"),
                "noise_bound_bits": projection(step["noise_bound_bits"], "bits"),
            }
            for step in plan.steps
        ],
        "counts": {key: projection(value, "count") for key, value in plan.counts.items()},
    }


PHASES = (
    ("profile", "profile"),
    ("key_generation_secret_key", "key_generation/secret_key"),
    ("key_generation_public_key", "key_generation/public_key"),
    ("key_generation_evaluation_keys", "key_generation/evaluation_keys"),
    ("client_encode", "client_input/encode"),
    ("scalar_subalgebra_and_range_check", "client_input/scalar_subalgebra_and_range_check"),
    ("client_encrypt", "client_input/encrypt"),
    ("load_mask_multiplication", "load_input/mask_multiplication"),
    ("load_broadcast_key_switches", "load_input/broadcast_key_switches"),
    ("load_modulus_switch", "load_input/modulus_switch"),
    ("equality_exponentiation", "select_eq_zero/equality_exponentiation"),
    ("embedded_one_multiplication", "select_eq_zero/embedded_one_multiplication"),
    ("indicator", "select_eq_zero/indicator"),
    ("select_multiplication", "select_eq_zero/select_multiplication"),
    ("output_masking", "output/output_masking"),
    ("unused_output_zeroing", "output/unused_output_zeroing"),
    ("decrypt", "open/decrypt"),
    ("decode", "open/decode"),
    ("release", "release"),
)
OPERATIONS = (
    "encryption",
    "decryption",
    "addition",
    "plaintext_multiplication",
    "tensor",
    "relinearization",
    "automorphism",
    "modulus_switch",
)
EVALUATION_PHASES = (
    "load_mask_multiplication",
    "load_broadcast_key_switches",
    "load_modulus_switch",
    "equality_exponentiation",
    "embedded_one_multiplication",
    "indicator",
    "select_multiplication",
    "output_masking",
    "unused_output_zeroing",
)


TAPE_SETUP_PHASES = ("profile", "key_generation", "client_input", "machine_setup", "open", "release")


def read_run(run_dir: Path, manifest_sha256: str) -> tuple[dict, dict]:
    """Return measured block and host from one pinned, verified byte snapshot."""
    verified = HARNESS.read_pinned_run(run_dir, manifest_sha256)
    report = verified["report"]
    records = [entry["json"]["path"] for entry in report["records"]
               if Path(entry["json"]["path"]).name.startswith("bgv-")]
    if len(records) != 1:
        raise SystemExit(f"{run_dir}: expected exactly one workload record")
    record = verified["documents"][records[0]]
    if record["outcome"] != "succeeded":
        raise SystemExit(f"{run_dir}: the workload did not succeed")
    nodes = record["phase_tree"]["nodes"]
    paths = []
    for node in nodes:
        parent = node["parent"]
        paths.append(node["label"] if parent in (None, 0) else f"{paths[parent]}/{node['label']}")
    by_path = {path: (index, node) for index, (path, node) in enumerate(zip(paths, nodes))}
    work_by_phase: dict = {}
    for entry in record["work_counters"]["entries"]:
        # A bit length or a level reported more than once in a phase is not a sum: keep the largest.
        peak = entry["label"].endswith("_bits") or entry["label"] == "output_level"
        work_by_phase.setdefault(entry["phase"], {})[entry["label"]] = entry["max_units" if peak else "total_units"]
    bytes_by_label = {entry["label"]: entry["max_bytes"] for entry in record["byte_counters"]["entries"]}

    def phase(path: str) -> dict:
        index, node = by_path[path]
        block = {
            "calls": measured(node["calls"], "count"),
            "wall_ns": measured(node["wall_inclusive_ns"], "nanoseconds"),
            "wall_ns_per_call": measured(node["wall_inclusive_ns"] // max(1, node["calls"]), "nanoseconds"),
        }
        for label, units in sorted(work_by_phase.get(index, {}).items()):
            unit = "work_units" if label == "model_work_units" else "bits" if label.endswith("_bits") else "count"
            block[label] = measured(units, unit)
        return block

    root = nodes[0]
    process = report["process"]
    config = report["context"]["config"]
    kind, name, shape = RUN_CONFIGS[config]
    geometry = work_by_phase[by_path["profile"][0]]
    declared = {entry["label"]: entry["value"] for entry in record["declared"]}
    block = {
        "workload": record["identity"]["workload"],
        "kind": kind,
        "config": config,
        "profile_name": name,
        "run": {
            "run_directory": run_dir.name,
            "manifest_sha256": verified["manifest_sha256"],
            "verdict": report["verdict"],
            "artifact": report["context"]["artifact"],
            "source_commit": report["context"]["source_commit"],
            "source_dirty": report["context"]["source_dirty"],
            "source_dirty_digest": report["context"]["source_dirty_digest"],
            "hardware": report["context"]["hardware"],
            "build_profile": report["context"]["profile"],
            "cache_policy": report["context"]["cache_policy"],
            "thermal_begin": record["process"]["thermal_begin"],
            "thermal_finish": record["process"]["thermal_finish"],
            "workers": measured(record["scheduling"]["workers"], "count"),
            "system_load_milli_begin": measured(record["process"]["load_milli_begin"], "count"),
            "system_load_milli_finish": measured(record["process"]["load_milli_finish"], "count"),
        },
        "geometry": {label: measured(units, "count") for label, units in sorted(geometry.items())},
        "process": {
            "peak_rss_bytes": measured(process["peak_rss_bytes"], "bytes"),
            "cpu_user_ns": measured(process["cpu_user_ns"], "nanoseconds"),
            "cpu_system_ns": measured(process["cpu_system_ns"], "nanoseconds"),
            "root_wall_ns": measured(root["wall_inclusive_ns"], "nanoseconds"),
            "root_unattributed_wall_ns": measured(root["wall_exclusive_ns"], "nanoseconds"),
        },
        "sizes": {label: measured(size, "bytes") for label, size in sorted(bytes_by_label.items())},
        "declared_model_values": {
            label: projection(value, "bytes" if "bytes" in label else "work_units")
            for label, value in sorted(declared.items())
        },
    }
    if kind == "equal_workload":
        block["phases"] = {key: phase(path) for key, path in PHASES}
        block["operation_profile_top_level"] = {
            operation: phase(f"operation_profile/{operation}") for operation in OPERATIONS
        }
    else:
        block["setup_phases"] = {key: phase(key) for key in TAPE_SETUP_PHASES}
        block["tape"] = phase("tape")
        block["instructions"] = {
            opcode: phase(f"tape/{opcode}") for opcode in OPCODES if f"tape/{opcode}" in by_path
        }
        block["final_zeroing_mask"] = phase("tape/final_zeroing_mask")
    return block, report["host"]


def evaluation_wall_ns(run: dict) -> int:
    """Wall time of the evaluation part of a run: what the encodings and tapes are compared on."""
    if run["kind"] == "equal_workload":
        return sum(run["phases"][key]["wall_ns"]["value"] for key in EVALUATION_PHASES)
    return run["tape"]["wall_ns"]["value"]


def representative_runs(runs: list) -> dict:
    """Per configuration, the run with the median evaluation time (the lower one of an even count)."""
    grouped: dict = {}
    for run in runs:
        grouped.setdefault(run["config"], []).append(run)
    out = {}
    for config, group in grouped.items():
        ordered = sorted(group, key=lambda run: (evaluation_wall_ns(run), run["run"]["run_directory"]))
        out[config] = ordered[(len(ordered) - 1) // 2]
    return out


def run_spread(runs: list) -> dict:
    """How far the repeated runs of each configuration lie apart."""
    grouped: dict = {}
    for run in runs:
        grouped.setdefault(run["config"], []).append(run)
    representative = representative_runs(runs)
    out = {}
    for config in sorted(grouped):
        group = grouped[config]
        walls = sorted(evaluation_wall_ns(run) for run in group)
        loads = [run["run"]["system_load_milli_begin"]["value"] for run in group]
        out[config] = {
            "runs": measured(len(group), "count"),
            "representative_run_directory": representative[config]["run"]["run_directory"],
            "evaluation_wall_ns_min": measured(walls[0], "nanoseconds"),
            "evaluation_wall_ns_median": measured(evaluation_wall_ns(representative[config]), "nanoseconds"),
            "evaluation_wall_ns_max": measured(walls[-1], "nanoseconds"),
            "max_over_min_permille": measured(walls[-1] * 1000 // max(1, walls[0]), "permille"),
            "peak_rss_bytes_max": measured(max(run["process"]["peak_rss_bytes"]["value"] for run in group), "bytes"),
            "system_load_milli_begin_min": measured(min(loads), "count"),
            "system_load_milli_begin_max": measured(max(loads), "count"),
        }
    return out


def sha256_of(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


def derived_blocks(runs: list) -> dict:
    """Everything recomputed from parameters and from the measured values in `runs`."""
    by_config = representative_runs(runs)
    out: dict = {"run_spread": run_spread(runs)}

    # Profiles.
    galois = {name: profile(name, shape).broadcast_steps() for name, shape in CANDIDATES.items()}
    out["candidates"] = {
        name: dict(
            profile_block(profile(name, shape), galois[name]),
            intended_class=CANDIDATE_CLASS[name],
            profile_identity=profile_identity(shape),
        )
        for name, shape in CANDIDATES.items()
    }
    out["measured_profiles"] = {}
    for config, (name, shape) in MEASURED_CONFIGS.items():
        p = profile(name, shape)
        block = profile_block(p, p.broadcast_steps())
        block["equal_workload_plan"] = plan_block(plan_equal_workload(p))
        block["minimal_main_primes_for_equal_workload"] = projection(
            minimal_main_primes(shape, plan_equal_workload), "count"
        )
        out["measured_profiles"][config] = block

    # Comparison of the two encodings at N = 2^16.
    sparse = by_config.get("bgv.f257.n16.q22x50.p2x60/sparse128")
    batching = by_config.get("bgv.derive.n16.t786433.q25x60.p3x60.d2/split65536")
    if sparse and batching:
        comparison = {}
        for key in (
            "scalar_subalgebra_and_range_check",
            "load_mask_multiplication",
            "load_broadcast_key_switches",
            "equality_exponentiation",
            "embedded_one_multiplication",
            "select_multiplication",
            "output_masking",
            "unused_output_zeroing",
            "key_generation_evaluation_keys",
        ):
            a = sparse["phases"][key]["wall_ns"]["value"]
            b = batching["phases"][key]["wall_ns"]["value"]
            comparison[key] = {
                "f257_sparse_wall_ns": measured(a, "nanoseconds"),
                "batching_wall_ns": measured(b, "nanoseconds"),
                "batching_over_sparse_permille": measured(b * 1000 // a if a else 0, "permille"),
            }
        for label, runs_pair in (("evaluation_total", (sparse, batching)),):
            totals = [sum(run["phases"][key]["wall_ns"]["value"] for key in EVALUATION_PHASES) for run in runs_pair]
            comparison[label] = {
                "f257_sparse_wall_ns": measured(totals[0], "nanoseconds"),
                "batching_wall_ns": measured(totals[1], "nanoseconds"),
                "batching_over_sparse_permille": measured(totals[1] * 1000 // totals[0], "permille"),
            }
        for label, key in (
            ("evaluation_keys_frame_bytes", "evaluation_keys_frame"),
            ("input_ciphertext_frame_bytes", "input_ciphertext_frame"),
        ):
            comparison[label] = {
                "f257_sparse": sparse["sizes"][key],
                "batching": batching["sizes"][key],
            }
        comparison["peak_rss_bytes"] = {
            "f257_sparse": sparse["process"]["peak_rss_bytes"],
            "batching": batching["process"]["peak_rss_bytes"],
        }
        out["encoding_comparison_n16"] = comparison

    # The same workload on both branches of its select.
    nonzero = by_config.get("bgv.f257.n16.q22x50.p2x60/sparse128.nonzero")
    if sparse and nonzero:
        branches = {
            key: {
                "zero_branch_wall_ns": measured(sparse["phases"][key]["wall_ns"]["value"], "nanoseconds"),
                "nonzero_branch_wall_ns": measured(nonzero["phases"][key]["wall_ns"]["value"], "nanoseconds"),
            }
            for key in EVALUATION_PHASES
        }
        branches["evaluation_total"] = {
            "zero_branch_wall_ns": measured(evaluation_wall_ns(sparse), "nanoseconds"),
            "nonzero_branch_wall_ns": measured(evaluation_wall_ns(nonzero), "nanoseconds"),
        }
        out["select_branch_comparison_n16"] = branches

    # Tape lowering: every instruction, the maximum-shape families and what fits.
    out["tape_lowering"] = tape_lowering_block()

    # One instruction of every opcode, measured through the encrypted costing harness.
    measurements = {}
    for config in (BOUNDED_TAPE_CONFIG, AFFINE_TAPE_CONFIG):
        run = by_config.get(config)
        if run is None:
            continue
        _, name, shape = RUN_CONFIGS[config]
        p = profile(name, shape)
        plan = cached_plan(shape, instruction_profile(name))
        keys = p.evaluation_key_bytes(p.broadcast_steps())
        projected = keys + plan["peak_working_bytes"]
        peak_rss = run["process"]["peak_rss_bytes"]["value"]
        tape_ns = run["tape"]["wall_ns"]["value"]
        measurements[config] = {
            "profile": name,
            "instructions": dict(run["instructions"], **{"final zeroing mask": run["final_zeroing_mask"]}),
            "tape_wall_ns": measured(tape_ns, "nanoseconds"),
            "tape_model_work_units": projection(plan["total"][UNITS], "work_units"),
            "picoseconds_per_work_unit": projection(
                tape_ns * 1000 // plan["total"][UNITS],
                "picoseconds",
                basis="measured wall time of the tape over its model work units",
            ),
            "memory": {
                "peak_rss_bytes": measured(peak_rss, "bytes"),
                "projected_evaluation_keys_bytes": projection(keys, "bytes"),
                "projected_peak_working_bytes": projection(plan["peak_working_bytes"], "bytes"),
                "projected_total_bytes": projection(projected, "bytes"),
                "measured_over_projected_permille": projection(
                    peak_rss * 1000 // projected,
                    "permille",
                    basis="measured peak resident memory over the projected keys and working set",
                ),
            },
        }
    out["tape_instruction_measurements"] = measurements

    # Class cost model: what each class needs against what its candidate has.
    classes: dict = {}
    bounded_name = "bgv.f257.n16.q22x50.p2x60"
    bounded = profile(bounded_name, CANDIDATES[bounded_name])
    bounded_block = class_block("bounded.v1", bounded_name)
    bounded_block["maximum_shape_wall_time"] = {
        "selects_then_output": {
            "ciphertext_multiplications": projection((MAX_INSTRUCTIONS - 1) * SELECT_MULTIPLICATIONS, "count"),
        },
        "loads_then_output": {
            "key_switches": projection((MAX_INSTRUCTIONS - 1) * bounded.broadcast_steps(), "count"),
            "plaintext_multiplications": projection(MAX_INSTRUCTIONS - 1, "count"),
        },
    }
    if sparse:
        ops = sparse["operation_profile_top_level"]
        multiplication_ns = sum(
            ops[key]["wall_ns_per_call"]["value"] for key in ("tensor", "relinearization", "modulus_switch")
        )
        load_ns = (
            sparse["phases"]["load_mask_multiplication"]["wall_ns"]["value"]
            + sparse["phases"]["load_broadcast_key_switches"]["wall_ns"]["value"]
            + sparse["phases"]["load_modulus_switch"]["wall_ns"]["value"]
        ) // sparse["phases"]["load_mask_multiplication"]["calls"]["value"]
        bounded_block["measured_inputs"] = {
            "multiplication_relinearization_switch_top_level_wall_ns": measured(multiplication_ns, "nanoseconds"),
            "load_input_top_level_wall_ns": measured(load_ns, "nanoseconds"),
        }
        bounded_block["maximum_shape_wall_time"]["selects_then_output"]["wall_ns_upper_estimate"] = projection(
            (MAX_INSTRUCTIONS - 1) * SELECT_MULTIPLICATIONS * multiplication_ns,
            "nanoseconds",
            basis="every multiplication charged at the measured top-level time",
        )
        bounded_block["maximum_shape_wall_time"]["loads_then_output"]["wall_ns_upper_estimate"] = projection(
            (MAX_INSTRUCTIONS - 1) * load_ns,
            "nanoseconds",
            basis="every load charged at the measured top-level time",
        )
    classes["bounded.v1"] = bounded_block

    affine_name = "bgv.f257.n14.q6x50.p2x60"
    affine = profile(affine_name, CANDIDATES[affine_name])
    affine_plan = plan_affine_map(affine)
    affine_block = class_block("affine.v1", affine_name)
    affine_block.update(
        {
            "affine_map_lowering": (
                "A proposal, not implemented: compile the tape to its affine map over the field and evaluate each"
                " output as one row product and one trace of the broadcast key switches."
            ),
            "affine_map_plan": plan_block(affine_plan),
            "minimal_main_primes_for_affine_map": projection(
                minimal_main_primes(CANDIDATES[affine_name], plan_affine_map), "count"
            ),
            "maximum_shape_affine_map": {
                "plaintext_multiplications": projection(2 * MAX_OUTPUTS + 1, "count"),
                "key_switches": projection(MAX_OUTPUTS * affine.broadcast_steps(), "count"),
                "work_units": projection(
                    MAX_OUTPUTS * affine.broadcast_steps() * affine.key_switch_units(affine.top)
                    + (2 * MAX_OUTPUTS + 1) * affine.plaintext_multiplication_units(affine.top),
                    "work_units",
                    basis="every operation charged at the top level",
                ),
            },
        }
    )
    probe = by_config.get("bgv.derive.n14.t257.q13x50.p2x60.d2/sparse128")
    if probe:
        probe_profile = profile(*MEASURED_CONFIGS[probe["config"]])
        ops = probe["operation_profile_top_level"]
        # Scale the measured top-level times of the probe chain by model units to the candidate chain.
        def scaled(operation: str, probe_units: int, candidate_units: int) -> int:
            return ops[operation]["wall_ns_per_call"]["value"] * candidate_units // probe_units

        key_switch_ns = scaled(
            "automorphism", probe_profile.key_switch_units(probe_profile.top), affine.key_switch_units(affine.top)
        )
        plain_ns = scaled(
            "plaintext_multiplication",
            probe_profile.plaintext_multiplication_units(probe_profile.top),
            affine.plaintext_multiplication_units(affine.top),
        )
        affine_block["scaled_inputs"] = {
            "key_switch_top_level_wall_ns": projection(
                key_switch_ns, "nanoseconds", basis="probe time scaled by the ratio of model work units"
            ),
            "plaintext_multiplication_top_level_wall_ns": projection(
                plain_ns, "nanoseconds", basis="probe time scaled by the ratio of model work units"
            ),
        }
        affine_block["maximum_shape_affine_map"]["wall_ns_upper_estimate"] = projection(
            MAX_OUTPUTS * affine.broadcast_steps() * key_switch_ns + (2 * MAX_OUTPUTS + 1) * plain_ns,
            "nanoseconds",
            basis="every operation charged at the scaled top-level time",
        )
    classes["affine.v1"] = affine_block

    refresh_name = "bgv.f257.n16.q32x50.p2x60"
    refresh_shape = CANDIDATES[refresh_name]
    refresh_block = class_block("refresh.v1", refresh_name)
    refresh_block["refresh_algorithm"] = (
        "not implemented (tasks C.8 and R.9). The families are planned as one segment between two refreshes;"
        " a refresh itself has no lowering, no work units and no noise rule here."
    )
    # What a maximal segment leaves for a refresh, against the depth the design memo cites.
    segment = FAMILIES["bounded.alternating_rank_chain"][2]
    segment_primes = tape_minimal_main_primes(refresh_shape, segment)
    secret_weight = 2 * (1 << refresh_shape[0]) // 3
    depth = math.ceil(math.log2(secret_weight) + math.log2(refresh_shape[1]))
    depth_primes = tape_minimal_main_primes(refresh_shape, _frontier(depth, 0, 1))
    refresh_block["refresh_room_projection"] = {
        "segment_family": "bounded.alternating_rank_chain",
        "main_primes_of_the_segment": projection(segment_primes, "count"),
        "main_primes_left_in_candidate": projection(refresh_shape[2][1] - segment_primes, "count"),
        "cited_bootstrapping_depth": number(
            depth,
            "count",
            "parameter",
            basis=(
                "ceil(log2(h) + log2(t)) for the expected weight h = 2N/3 of a uniform ternary secret, the depth"
                " expression the design memo cites from Chen and Han (2018) for thin BGV bootstrapping. Not"
                " re-derived here and not implemented."
            ),
        ),
        "main_primes_of_a_chain_of_that_depth": projection(
            depth_primes,
            "count",
            basis="one load, that many sequential squarings and one output under the lowering of this summary",
        ),
        "fits_beside_the_segment": depth_primes is not None and segment_primes + depth_primes <= refresh_shape[2][1],
    }
    classes["refresh.v1"] = refresh_block
    out["class_cost_model"] = classes

    # Proof work: labelled projections of relation sizes; no proof is built here.
    out["proof_work_projection"] = proof_work_block()

    # Values of the resource-contract inputs that the contract marks open for C.3.
    inputs = {}
    for name, shape in CANDIDATES.items():
        p = profile(name, shape)
        load_units = p.plaintext_multiplication_units(p.top) + p.broadcast_steps() * p.key_switch_units(p.top)
        inputs[name] = {
            "intended_class": CANDIDATE_CLASS[name],
            "ram_lfe.ciphertext_bytes": projection(p.ciphertext_bytes(p.top), "bytes"),
            "ram_lfe.input_ciphertexts": projection(-(-INPUT_SLOTS // p.slots()), "count"),
            "ram_lfe.output_ciphertexts": projection(-(-MAX_OUTPUTS // p.slots()), "count"),
            "ram_lfe.evaluation_key_bytes": projection(p.evaluation_key_bytes(p.broadcast_steps()), "bytes"),
            "ram_lfe.multiplication_work_units": projection(
                p.multiplication_units(p.top),
                "work_units",
                basis="tensor product and relinearization at the top level; the modulus switches of a product are not included",
            ),
            "ram_lfe.plain_operation_work_units": projection(
                load_units,
                "work_units",
                basis=(
                    "LoadInput, the costliest affine.v1 instruction under the lowering: one mask multiplication"
                    " and one key switch per broadcast step, at the top level"
                ),
            ),
            "proposed_additional_inputs": {
                "ram_lfe.key_switch_work_units": projection(p.key_switch_units(p.top), "work_units"),
                "ram_lfe.plaintext_multiplication_work_units": projection(
                    p.plaintext_multiplication_units(p.top), "work_units"
                ),
                "ram_lfe.modulus_switch_work_units": projection(p.switch_down_units(p.top), "work_units"),
                "ram_lfe.input_load_key_switches": projection(p.broadcast_steps(), "count"),
            },
            "budget_formulas_against_planned_families": contract_budget_check(name, shape, load_units),
        }
    out["resource_contract_inputs"] = inputs
    return out


def work_block(work: list) -> dict:
    return {
        field: projection(value, "work_units" if field == "work_units" else "count")
        for field, value in zip(WORK_FIELDS, work)
    }


def opcode_label(tag: int) -> str:
    return OPCODES[tag] if tag < len(OPCODES) else "final zeroing mask"


def tape_plan_block(shape: tuple, tape: tuple) -> dict:
    """What planning one tape on one profile gives, with the fewest primes that would hold it."""
    plan = cached_plan(shape, tape)
    block: dict = {"fits": plan["fits"]}
    if plan["fits"]:
        block.update(
            {
                "output_level": projection(plan["level"], "count"),
                "output_noise_bound_bits": projection(plan["bound"].bit_length(), "bits"),
                "output_capacity_bits": projection(plan["capacity"].bit_length(), "bits"),
                "work": work_block(plan["total"]),
                "peak_persistent_ciphertext_bytes": projection(plan["peak_persistent_bytes"], "bytes"),
                "peak_working_bytes": projection(plan["peak_working_bytes"], "bytes"),
            }
        )
    else:
        block.update(
            {
                "refused_at_instruction": projection(plan["instruction"], "count"),
                "refused_opcode": opcode_label(plan["tag"]),
            }
        )
    minimal = tape_minimal_main_primes(shape, tape)
    block["minimal_main_primes"] = None if minimal is None else projection(minimal, "count")
    flooding = []
    for log2_releases, kappa in SANITIZATION_PROJECTIONS:
        flooded = cached_plan(shape, tape, (log2_releases, kappa))
        entry: dict = {
            "log2_releases": number(log2_releases, "count", "parameter"),
            "kappa": number(kappa, "bits", "parameter"),
            "fits": flooded["fits"],
        }
        if "flooded_bound" in flooded:
            entry["flooded_noise_bound_bits"] = projection(flooded["flooded_bound"].bit_length(), "bits")
        minimal_flooded = tape_minimal_main_primes(shape, tape, (log2_releases, kappa))
        entry["minimal_main_primes"] = None if minimal_flooded is None else projection(minimal_flooded, "count")
        flooding.append(entry)
    block["with_flooding_sanitization"] = flooding
    return block


def candidate_families(name: str) -> list:
    """Family names planned on a candidate: every family its class admits."""
    affine_only = CANDIDATE_CLASS[name] == "affine.v1"
    return [family for family, (cls, _, _) in FAMILIES.items() if cls == "affine.v1" or not affine_only]


def instruction_profile(name: str) -> tuple:
    return INSTRUCTION_PROFILE_AFFINE if CANDIDATE_CLASS[name] == "affine.v1" else INSTRUCTION_PROFILE_BOUNDED


def tape_lowering_block() -> dict:
    families = {}
    for family, (cls, description, tape) in FAMILIES.items():
        families[family] = {
            "class": cls,
            "description": description,
            "instructions": number(len(tape), "count", "parameter"),
            "outputs": number(sum(1 for item in tape if item[0] == OUTPUT), "count", "parameter"),
            "peak_rank": number(peak_rank(tape), "count", "parameter"),
        }
    candidates = {}
    for name, shape in CANDIDATES.items():
        plan = cached_plan(shape, instruction_profile(name))
        if not plan["fits"]:
            raise SystemExit(f"{name}: the instruction profile tape does not fit")
        costs = {
            OPCODES[tag]: work_block(plan["costliest"][tag])
            for tag in range(len(OPCODES))
            if plan["instructions"][tag]
        }
        costs["final zeroing mask"] = work_block(plan["by_opcode"][FINAL_MASK])
        ranks = (0,) if CANDIDATE_CLASS[name] == "affine.v1" else (0, SELECT_MULTIPLICATIONS, BOUNDED_MAX_RANK)
        candidates[name] = {
            "intended_class": CANDIDATE_CLASS[name],
            "instruction_costs": costs,
            "families": {family: tape_plan_block(shape, FAMILIES[family][2]) for family in candidate_families(name)},
            "sequential_constant_multiplications_that_fit": {
                f"after_rank_{rank}": {
                    "fit": projection(frontier_scales(shape, rank), "count"),
                    "instruction_limit": number(MAX_INSTRUCTIONS - 1 - rank - MAX_OUTPUTS, "count", "parameter"),
                }
                for rank in ranks
            },
        }
    return {
        "harness": HARNESS_SOURCE,
        "lowering": LOWERING_TEXT,
        "level_policy": LEVEL_POLICY_TEXT,
        "shape": {
            "registers": number(REGISTERS, "count", "parameter"),
            "state_lanes": number(STATE_LANES, "count", "parameter"),
            "input_slots": number(INPUT_SLOTS, "count", "parameter"),
            "max_instructions": number(MAX_INSTRUCTIONS, "count", "parameter"),
            "max_outputs": number(MAX_OUTPUTS, "count", "parameter"),
            "bounded_max_rank": number(BOUNDED_MAX_RANK, "count", "parameter"),
            "refresh_max_rank_between_refreshes": number(REFRESH_MAX_RANK_BETWEEN_REFRESHES, "count", "parameter"),
            "refresh_max_refreshes": number(REFRESH_MAX_REFRESHES, "count", "parameter"),
            "select_multiplications": number(SELECT_MULTIPLICATIONS, "count", "parameter"),
            "largest_main_primes_of_the_implementation": number(MAX_BASIS_PRIMES - 2, "count", "parameter"),
        },
        "instruction_cost_basis": (
            "the costliest instance of each opcode in a tape that executes every opcode of the class once on"
            " operands loaded at the top level; copies, constants and plaintext additions cost no work unit"
        ),
        "working_bytes_basis": (
            "peak_persistent_ciphertext_bytes is the residues of the input, the four registers, the 32 lanes and"
            " the output accumulator at an instruction boundary. peak_working_bytes adds the temporaries named in"
            " the harness and the tensor and key-switch scratch of one operation. Evaluation keys are not included."
        ),
        "sanitization_projection": (
            "A projection of noise flooding, not a construction: with E = ceil(V / t), a uniform flood of"
            " half-width F = H * N * E * 2^kappa on every error coefficient hides a shift of 2E per release at"
            " statistical distance 2^-kappa over H releases, and the flooded, re-randomized output has the bound"
            " V + t*F + V_fresh. H and kappa are illustrative parameters nobody has selected. Flooding alone"
            " does not hide the second ciphertext component; the construction and its proof are task R.11."
        ),
        "families": families,
        "candidates": candidates,
    }


def class_block(cls: str, name: str) -> dict:
    """Which maximum-shape families of a class fit its candidate, and what the others need."""
    shape = CANDIDATES[name]
    fits, refused = [], []
    needed = []
    exceeds = False
    for family in candidate_families(name):
        tape = FAMILIES[family][2]
        (fits if cached_plan(shape, tape)["fits"] else refused).append(family)
        minimal = tape_minimal_main_primes(shape, tape)
        if minimal is None:
            exceeds = True
        else:
            needed.append(minimal)
    return {
        "profile": name,
        "main_primes_in_candidate": number(shape[2][1], "count", "parameter"),
        "maximum_shape_families_that_fit": fits,
        "maximum_shape_families_refused": refused,
        "holds_every_planned_family": not refused,
        "main_primes_for_every_planned_family": None if exceeds else projection(max(needed), "count"),
        "note": (
            "Lowered instruction by instruction the candidate does not hold the maximum shape of its class:"
            " a sequential constant multiplication costs log2((t-1)/2) = 7 bits of capacity and does not raise"
            " the logical rank. Per family: tape_lowering.candidates."
            if refused
            else "Every planned maximum-shape family fits. Per family: tape_lowering.candidates."
        ),
    }


# TODO(R.11, R.3, R.7, R.8): the relation sizes below are projections under a stated layout.
# Replace them by the rows, cells and proof bytes of the relations those tasks build.
def limbs_of(bits: int) -> int:
    """16-bit limbs of a value of `bits` bits."""
    return -(-bits // 16)


def input_relation_block(p: Profile) -> dict:
    """Projected size of the client's input well-formedness relation for one encoding.

    Layout assumed (task R.11 selects the real one): the witness is the ternary
    mask u, the errors e0 and e1 and the slot scalars. Per main prime the
    relation transforms u, multiplies point-wise by the two public-key
    components and transforms both products back (three transforms and 4N
    further residue multiplications), then checks c0 = b*u + t*e0 + m and
    c1 = a*u + t*e1 coefficient-wise with one small quotient each. The
    plaintext is tied to its slots by one inverse slot transform modulo t.
    Every residue multiplication is range-checked through a quotient and a
    remainder in 16-bit limbs.
    """
    n = p.degree
    primes = p.top + 1
    slots = p.slots()
    butterflies = n // 2 * p.log_degree
    chain_multiplications = primes * (3 * butterflies + 4 * n)
    slot_butterflies = slots // 2 * (slots.bit_length() - 1)
    chain_limbs = limbs_of(max(prime.bit_length() for prime in p.main))
    plaintext_limbs = limbs_of(p.t.bit_length())
    equations = 2 * primes * n
    range_checked = (
        2 * chain_limbs * chain_multiplications
        + 2 * plaintext_limbs * slot_butterflies
        + 3 * n
        + slots
        + equations
    )
    encoding_specific = 2 * plaintext_limbs * slot_butterflies + slots
    rows = chain_multiplications + slot_butterflies
    return {
        "secret_coefficients_range_checked": projection(3 * n, "count"),
        "plaintext_slots_range_checked": projection(slots, "count"),
        "plaintext_coefficients_fixed_to_zero": projection(n - slots, "count"),
        "slot_transform_butterflies": projection(slot_butterflies, "count"),
        "slot_transform_modulus_bits": projection(p.t.bit_length(), "bits"),
        "ciphertext_coefficient_equations": projection(equations, "count"),
        "chain_residue_multiplications": projection(chain_multiplications, "count"),
        "limbs_per_chain_residue": projection(chain_limbs, "count"),
        "limb_products": projection(
            chain_limbs * chain_limbs * chain_multiplications + plaintext_limbs * plaintext_limbs * slot_butterflies,
            "count",
        ),
        "range_checked_limbs": projection(range_checked, "count"),
        "rows_at_one_multiplication_per_row": projection(rows, "count"),
        "log2_rows_at_one_multiplication_per_row": projection(round(math.log2(rows), 2), "bits"),
        "encoding_specific_range_checked_limbs": projection(encoding_specific, "count"),
        "encoding_specific_share_ppm": projection(encoding_specific * 1_000_000 // range_checked, "ppm"),
    }


def execution_relation_block(p: Profile, units: int) -> dict:
    """Projected size of a relation that constrains every residue multiplication of an evaluation."""
    chain_limbs = limbs_of(max(prime.bit_length() for prime in p.main + p.special))
    return {
        "residue_multiplications": projection(units, "count", basis="the model work units of the evaluation"),
        "limb_products": projection(chain_limbs * chain_limbs * units, "count"),
        "range_checked_limbs": projection(2 * chain_limbs * units, "count"),
        "log2_rows_at_one_multiplication_per_row": projection(round(math.log2(units), 2), "bits"),
    }


INPUT_RELATION_CONFIGS = (
    ("bgv.f257.n14.q6x50.p2x60/sparse128", "bgv.f257.n14.q6x50.p2x60", CANDIDATES["bgv.f257.n14.q6x50.p2x60"]),
    ("bgv.f257.n16.q22x50.p2x60/sparse128", *MEASURED_CONFIGS["bgv.f257.n16.q22x50.p2x60/sparse128"]),
    (
        "bgv.derive.n16.t786433.q25x60.p3x60.d2/split65536",
        *MEASURED_CONFIGS["bgv.derive.n16.t786433.q25x60.p3x60.d2/split65536"],
    ),
)


def proof_work_block() -> dict:
    execution = {}
    for name, shape in CANDIDATES.items():
        p = profile(name, shape)
        entries = {}
        for family in candidate_families(name):
            plan = cached_plan(shape, FAMILIES[family][2])
            if plan["fits"]:
                entries[family] = execution_relation_block(p, plan["total"][UNITS])
        execution[name] = entries
    return {
        "status": "projection only: no input, execution or opening proof exists (tasks R.11, R.3, R.7, R.8)",
        "limb_model": (
            "16-bit limbs over a 64-bit proof field as in the design memo: a residue below 2^62 is four limbs,"
            " a product of two residues is 16 limb products, and its quotient and remainder are range-checked"
            " limb by limb"
        ),
        "input_relation_layout": input_relation_block.__doc__.split("\n\n", 1)[1].strip().replace("\n    ", " "),
        "input_relation": {
            config: input_relation_block(profile(name, shape)) for config, name, shape in INPUT_RELATION_CONFIGS
        },
        "execution_relation_layout": (
            "one constrained residue multiplication per model work unit of the evaluation; a relation that"
            " batches or amortizes transforms would be smaller, and one that covers the padded maximum shape"
            " for every tape would be larger"
        ),
        "execution_relation": execution,
    }


def contract_budget_check(name: str, shape: tuple, load_units: int) -> dict:
    """The budget formulas of specs/zk_resource_contract.json against the planned families."""
    p = profile(name, shape)
    planned = {
        family: cached_plan(shape, FAMILIES[family][2]) for family in candidate_families(name)
    }
    fitting = {family: plan["total"][UNITS] for family, plan in planned.items() if plan["fits"]}

    def against(formula: str, value: int, families: list) -> dict:
        largest = max(families, key=lambda family: fitting[family])
        return {
            "formula": formula,
            "formula_value": projection(value, "work_units"),
            "largest_planned_family": largest,
            "largest_planned_work_units": projection(fitting[largest], "work_units"),
            "covers_every_planned_family_that_fits": fitting[largest] <= value,
        }

    affine = [family for family in fitting if FAMILIES[family][0] == "affine.v1"]
    check = {
        "ram_lfe.affine_evaluation_work_units": against(
            "ram_lfe.shape_max_instructions * ram_lfe.plain_operation_work_units",
            MAX_INSTRUCTIONS * load_units,
            affine,
        )
    }
    if CANDIDATE_CLASS[name] != "affine.v1":
        check["ram_lfe.bounded_evaluation_work_units"] = against(
            "ram_lfe.shape_max_instructions * ram_lfe.multiplications_per_instruction * ram_lfe.multiplication_work_units",
            MAX_INSTRUCTIONS * SELECT_MULTIPLICATIONS * p.multiplication_units(p.top),
            list(fitting),
        )
    return check


def summary_frame(runs: list, host: dict, root: Path = ROOT) -> dict:
    """The part of the summary that is neither a run nor derived from one."""
    return {
        "schema": SCHEMA,
        "task": "C.3",
        "scope": (
            "Cost model and host measurements of the RNS-BGV starting candidates. It qualifies no profile,"
            " establishes no security level and grants no runtime permission."
        ),
        "generator": "scripts/fhe_bgv_cost_model.py",
        "classification": {
            "measured": "copied from an accepted record of scripts/zk_resource_harness.py on the host below, or a sum, a ratio or an extreme of such values",
            "projection": "computed from profile parameters by the noise rules, the work-unit model, the tape lowering, a stated relation layout, a scaled measurement or the core-SVP sanity formula",
            "parameter": "an exact input that defines a profile, a workload shape or an illustrative setting of a projection",
            "estimator": "copied from the tracked output record of scripts/fhe_bgv_lattice_estimator.sage (the Lattice Estimator at its pinned commit), or a minimum, a count or a difference of such values",
        },
        "host": host,
        "measurement_notes": [
            "Single-threaded scalar reference path; no accelerated kernel exists for 50 to 60-bit moduli.",
            "Raw harness runs stay under the ignored dist/zk-resource-harness/; only this summary is tracked.",
            "The host ran other builds during the runs; the recorded system load is part of each run. Each"
            " configuration ran several times; run_spread gives the fastest and the slowest, and every derived"
            " time uses the run with the median evaluation time.",
            "Cache policy: every run is a fresh process that builds its transforms and keys itself; no table,"
            " key or proof artifact is cached between runs, so warm describes the file cache of the binary only.",
            "The batching comparator uses 60-bit main primes against the 50-bit primes of the candidates: at"
            " t = 786433 a product of two values at the rounding floor is about 87 bits, which one 50-bit prime"
            " per multiplication cannot bring back.",
        ],
        "security_estimate": {
            "status": (
                "Estimates only. No profile is qualified and no security level is claimed: the estimator"
                " numbers hold under the assumptions and limits lattice_estimator.what_is_estimated and"
                " lattice_estimator.not_covered state, and the parameters have not been reviewed."
            ),
            "lattice_estimator": estimator_block(root),
            "core_svp_sanity": (
                "primal uSVP on the largest modulus Q*P with error sigma = sqrt(10.5) and a ternary secret,"
                " geometric series assumption, 2016 estimate. Reported: the block size beta, the core-SVP"
                " exponents 0.292*beta (classical) and 0.265*beta (quantum), and 0.292*beta + 16.4 +"
                " log2(8*d) in the style of the BDGL16 reduction cost model. Not a substitute for the"
                " Lattice Estimator: no dual, hybrid or algebraic attack is costed. The estimator block"
                " compares these numbers with its own primal uSVP result for every profile."
            ),
        },
        "runs": runs,
    }


def build_summary(run_dirs: list, *, manifest_sha256: list[str]) -> dict:
    """Build only from unique external pins and their verified run documents."""
    if not run_dirs or len(run_dirs) != len(manifest_sha256):
        raise ValueError("exactly one external manifest SHA-256 is required per run directory")
    if any(not isinstance(pin, str) or not re.fullmatch(r"[0-9a-f]{64}", pin)
           for pin in manifest_sha256):
        raise ValueError("every external manifest pin must be a SHA-256 digest")
    if len(set(manifest_sha256)) != len(manifest_sha256):
        raise ValueError("one sealed run cannot be counted as multiple measurements")
    runs = []
    hosts = []
    for run_dir, pin in zip(run_dirs, manifest_sha256):
        block, host = read_run(run_dir, pin)
        runs.append(block)
        hosts.append(host)
    runs.sort(key=lambda run: (run["config"], run["run"]["run_directory"]))
    host = hosts[0]
    if any(other != host for other in hosts):
        raise SystemExit("the runs were taken on different hosts")
    missing = sorted(set(RUN_CONFIGS) - {run["config"] for run in runs})
    if missing:
        raise SystemExit(f"no run of {', '.join(missing)}")
    summary = summary_frame(
        runs,
        {
            "hardware_record": runs[0]["run"]["hardware"],
            "model": host["model"],
            "cpu": host["cpu"],
            "machine": host["machine"],
            "system": host["system"],
            "release": host["release"],
            "logical_cpus": measured(host["logical_cpus"], "count"),
            "physical_memory_bytes": measured(host["physical_memory_bytes"], "bytes"),
        },
    )
    summary.update(derived_blocks(runs))
    return summary


def rederive(summary: dict, root: Path = ROOT) -> dict:
    """The summary rebuilt from its own measured runs and the tracked estimator record."""
    rebuilt = summary_frame(summary["runs"], summary["host"], root)
    rebuilt.update(derived_blocks(summary["runs"]))
    return rebuilt


def render(summary: dict) -> str:
    return json.dumps(summary, indent=1, sort_keys=True) + "\n"


# ---------------------------------------------------------------------------
# The view of the summary that the Rust test reads
# ---------------------------------------------------------------------------


def _profile_lines(block: dict) -> list:
    lines = [f"{key} = {item['value']}" for key, item in block["shape"].items()]
    lines += [
        f"first_main_prime = {block['first_main_prime']['value']}",
        f"last_main_prime = {block['last_main_prime']['value']}",
        "special_prime_values = " + ",".join(str(item["value"]) for item in block["special_primes"]),
    ]
    for key in (
        "modulus_bits",
        "special_modulus_bits",
        "key_switch_digits",
        "scalar_slots",
        "slot_mask_l1_norm",
        "broadcast_key_switches",
        "fresh_noise_bound_bits",
        "key_switch_noise_bound_bits",
    ):
        lines.append(f"{key} = {block[key]['value']}")
    lines += [f"size.{key} = {item['value']}" for key, item in block["sizes"].items()]
    lines += [f"work.{key} = {item['value']}" for key, item in block["work_units_top_level"].items()]
    return lines


def _optional(item: Optional[dict]) -> str:
    return "none" if item is None else str(item["value"])


def model_vectors_text(summary: dict) -> str:
    """Every number of the summary that the Rust model has to reproduce, as `key = value` sections.

    crates/iroha_fhe/tests/bgv_cost_model_vectors.rs recomputes each value with
    the Rust cost model, noise rules, slot encoding and costing harness. The
    file is a view of the summary, not of this script's model: it is rendered
    from the values the summary carries.
    """
    lines = [
        "# Generated by scripts/fhe_bgv_cost_model.py from specs/fhe_bgv_cost_summary.json. Do not edit.",
        "# Every value is recomputed by crates/iroha_fhe/tests/bgv_cost_model_vectors.rs.",
        "",
        "[shape]",
    ]
    lowering = summary["tape_lowering"]
    lines += [f"{key} = {item['value']}" for key, item in lowering["shape"].items()]
    lines.append("opcodes = " + ",".join(OPCODES))
    for name, block in summary["candidates"].items():
        lines += ["", f"[candidate {name}]", f"identity = {block['profile_identity']}"]
        lines.append(f"intended_class = {block['intended_class']}")
        lines += _profile_lines(block)
        inputs = summary["resource_contract_inputs"][name]
        for key, item in inputs.items():
            if key.startswith("ram_lfe."):
                lines.append(f"contract.{key} = {item['value']}")
        for key, item in inputs["proposed_additional_inputs"].items():
            lines.append(f"proposed.{key} = {item['value']}")
        for key, check in inputs["budget_formulas_against_planned_families"].items():
            lines.append(f"budget.{key}.formula_value = {check['formula_value']['value']}")
            lines.append(f"budget.{key}.largest_planned_family = {check['largest_planned_family']}")
            lines.append(f"budget.{key}.largest_planned_work_units = {check['largest_planned_work_units']['value']}")
            lines.append(f"budget.{key}.covers = {int(check['covers_every_planned_family_that_fits'])}")
    for config, block in summary["measured_profiles"].items():
        lines += ["", f"[profile {config}]"]
        lines += _profile_lines(block)
        lines.append(
            f"minimal_main_primes_for_equal_workload = {block['minimal_main_primes_for_equal_workload']['value']}"
        )
    for name, block in lowering["candidates"].items():
        for opcode, work in block["instruction_costs"].items():
            lines += ["", f"[instruction {name} {opcode}]"]
            lines += [f"{field} = {work[field]['value']}" for field in WORK_FIELDS]
        lines += ["", f"[frontier {name}]"]
        for key, item in block["sequential_constant_multiplications_that_fit"].items():
            lines.append(f"{key} = {item['fit']['value']}")
            lines.append(f"{key}.instruction_limit = {item['instruction_limit']['value']}")
        for family, plan in block["families"].items():
            lines += ["", f"[tape {name} {family}]", f"fits = {int(plan['fits'])}"]
            if plan["fits"]:
                for key in ("output_level", "output_noise_bound_bits", "output_capacity_bits"):
                    lines.append(f"{key} = {plan[key]['value']}")
                lines += [f"{field} = {plan['work'][field]['value']}" for field in WORK_FIELDS]
                for key in ("peak_persistent_ciphertext_bytes", "peak_working_bytes"):
                    lines.append(f"{key} = {plan[key]['value']}")
            else:
                lines.append(f"refused_at_instruction = {plan['refused_at_instruction']['value']}")
                lines.append(f"refused_opcode = {plan['refused_opcode']}")
            lines.append(f"minimal_main_primes = {_optional(plan['minimal_main_primes'])}")
            for entry in plan["with_flooding_sanitization"]:
                prefix = f"flooding.{entry['log2_releases']['value']}.{entry['kappa']['value']}"
                lines.append(f"{prefix}.fits = {int(entry['fits'])}")
                if "flooded_noise_bound_bits" in entry:
                    lines.append(f"{prefix}.noise_bound_bits = {entry['flooded_noise_bound_bits']['value']}")
                lines.append(f"{prefix}.minimal_main_primes = {_optional(entry['minimal_main_primes'])}")
    refresh = summary["class_cost_model"]["refresh.v1"]["refresh_room_projection"]
    lines += [
        "",
        "[refresh room]",
        f"segment_family = {refresh['segment_family']}",
        f"main_primes_of_the_segment = {refresh['main_primes_of_the_segment']['value']}",
        f"cited_bootstrapping_depth = {refresh['cited_bootstrapping_depth']['value']}",
        f"main_primes_of_a_chain_of_that_depth = {_optional(refresh['main_primes_of_a_chain_of_that_depth'])}",
    ]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Tables embedded in the specifications
# ---------------------------------------------------------------------------

COMPARISON_SPEC = "specs/ram_lfe_plaintext_packing.md"
CANDIDATE_SPEC = "specs/ram_lfe_encryption_replacement.md"
COMPARISON_MARKER = "fhe-bgv-encoding-comparison"
CANDIDATE_MARKER = "fhe-bgv-candidates"
CLASS_FIT_MARKER = "fhe-bgv-class-fit"
INSTRUCTION_MARKER = "fhe-bgv-instruction-costs"
INPUT_PROOF_MARKER = "fhe-bgv-input-proof-projection"
ESTIMATOR_MARKER = "fhe-bgv-lattice-estimator"
ESTIMATOR_ATTACKS_MARKER = "fhe-bgv-lattice-estimator-attacks"
ESTIMATOR_PROPOSALS_MARKER = "fhe-bgv-lattice-estimator-proposals"
SPARSE_CONFIG = "bgv.f257.n16.q22x50.p2x60/sparse128"
BATCHING_CONFIG = "bgv.derive.n16.t786433.q25x60.p3x60.d2/split65536"
BOUNDED_TAPE_CONFIG = "bgv.f257.n16.q22x50.p2x60/tape_profile"
AFFINE_TAPE_CONFIG = "bgv.f257.n14.q6x50.p2x60/tape_profile"


def _milliseconds(nanoseconds: int) -> str:
    return f"{nanoseconds / 1e6:,.1f} ms"


def _mebibytes(count: int) -> str:
    return f"{count / 2**20:,.1f} MiB"


def comparison_table(summary: dict) -> str:
    """The measured comparison of the two encodings at N = 2^16, as Markdown."""
    comparison = summary["encoding_comparison_n16"]
    runs = representative_runs(summary["runs"])
    spread = summary["run_spread"]
    sparse = runs[SPARSE_CONFIG]
    batching = runs[BATCHING_CONFIG]

    def count(run: dict, phase: str, label: str) -> int:
        return run["phases"][phase][label]["value"]

    rows = [
        ("Scalar-subalgebra and range check of the plaintext", "scalar_subalgebra_and_range_check", ""),
        ("Slot masks of two loads", "load_mask_multiplication", ""),
        (
            "Broadcasts of two loads ({} and {} key switches)".format(
                count(sparse, "load_broadcast_key_switches", "key_switches"),
                count(batching, "load_broadcast_key_switches", "key_switches"),
            ),
            "load_broadcast_key_switches",
            "",
        ),
        (
            "Equality exponentiation ({} and {} multiplications)".format(
                count(sparse, "equality_exponentiation", "ciphertext_multiplications"),
                count(batching, "equality_exponentiation", "ciphertext_multiplications"),
            ),
            "equality_exponentiation",
            "",
        ),
        ("Multiplication by the embedded one", "embedded_one_multiplication", ""),
        ("Select multiplication", "select_multiplication", ""),
        ("Output masks of two outputs", "output_masking", ""),
        ("Unused-output zeroing", "unused_output_zeroing", ""),
        ("Evaluation total", "evaluation_total", ""),
        ("Evaluation-key generation", "key_generation_evaluation_keys", ""),
    ]
    lines = [
        "| Part of the equal workload | F257 sparse, 128 slots | t = 786433, 65,536 slots | batching / sparse |",
        "| --- | ---: | ---: | ---: |",
    ]
    for label, key, _ in rows:
        entry = comparison[key]
        lines.append(
            "| {} | {} | {} | {:.2f} |".format(
                label,
                _milliseconds(entry["f257_sparse_wall_ns"]["value"]),
                _milliseconds(entry["batching_wall_ns"]["value"]),
                entry["batching_over_sparse_permille"]["value"] / 1000,
            )
        )
    lines.append(
        "| Evaluation total, fastest to slowest of {} and {} runs | {} to {} | {} to {} | |".format(
            spread[SPARSE_CONFIG]["runs"]["value"],
            spread[BATCHING_CONFIG]["runs"]["value"],
            _milliseconds(spread[SPARSE_CONFIG]["evaluation_wall_ns_min"]["value"]),
            _milliseconds(spread[SPARSE_CONFIG]["evaluation_wall_ns_max"]["value"]),
            _milliseconds(spread[BATCHING_CONFIG]["evaluation_wall_ns_min"]["value"]),
            _milliseconds(spread[BATCHING_CONFIG]["evaluation_wall_ns_max"]["value"]),
        )
    )
    for label, key in (
        ("Evaluation keys (canonical frames)", "evaluation_keys_frame_bytes"),
        ("Input ciphertext (canonical frame)", "input_ciphertext_frame_bytes"),
        ("Process peak resident memory", "peak_rss_bytes"),
    ):
        a, b = comparison[key]["f257_sparse"]["value"], comparison[key]["batching"]["value"]
        lines.append("| {} | {} | {} | {:.2f} |".format(label, _mebibytes(a), _mebibytes(b), b / a))
    lines.append(
        "| Main and special primes | {} + {} of {} and {} bits | {} + {} of {} and {} bits | |".format(
            sparse["geometry"]["main_primes"]["value"],
            sparse["geometry"]["special_primes"]["value"],
            RUN_CONFIGS[SPARSE_CONFIG][2][2][0],
            RUN_CONFIGS[SPARSE_CONFIG][2][3][0],
            batching["geometry"]["main_primes"]["value"],
            batching["geometry"]["special_primes"]["value"],
            RUN_CONFIGS[BATCHING_CONFIG][2][2][0],
            RUN_CONFIGS[BATCHING_CONFIG][2][3][0],
        )
    )
    lines.append(
        "| System load at the start of the run | {:.1f} | {:.1f} | |".format(
            sparse["run"]["system_load_milli_begin"]["value"] / 1000,
            batching["run"]["system_load_milli_begin"]["value"] / 1000,
        )
    )
    return "\n".join(lines)


def candidate_table(summary: dict) -> str:
    """Sizes, work units and sanity numbers of the three candidates, as Markdown."""
    lines = [
        "| Candidate | Class shape | log2 Q*P | Ciphertext frame | Evaluation keys | Multiplication work units"
        " | Core-SVP classical / quantum | BDGL16-style classical |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for name, block in summary["candidates"].items():
        sanity = block["security_sanity"]
        lines.append(
            "| `{}` | {} | {} | {} | {} | {:,} | {} / {} bits | {} bits |".format(
                name,
                block["intended_class"],
                sanity["log2_largest_modulus"]["value"],
                _mebibytes(block["sizes"]["ciphertext_frame_bytes_top_level"]["value"]),
                _mebibytes(block["sizes"]["evaluation_keys_frame_bytes"]["value"]),
                block["work_units_top_level"]["multiplication_with_relinearization"]["value"],
                sanity["core_svp_classical_bits"]["value"],
                sanity["core_svp_quantum_bits"]["value"],
                sanity["bdgl16_style_classical_bits"]["value"],
            )
        )
    return "\n".join(lines)


def class_fit_table(summary: dict) -> str:
    """What each maximum-shape family needs against what each candidate has, as Markdown."""
    lowering = summary["tape_lowering"]
    flooding = SANITIZATION_PROJECTIONS[0]
    lines = [
        "| Candidate (main primes) | Family | Planned result | Main primes needed"
        f" | With flooding (2^{flooding[0]} releases, 2^-{flooding[1]}) |",
        "| --- | --- | --- | ---: | ---: |",
    ]

    def primes(item: Optional[dict]) -> str:
        limit = lowering["shape"]["largest_main_primes_of_the_implementation"]["value"]
        return f"more than {limit}" if item is None else str(item["value"])

    for name, block in lowering["candidates"].items():
        have = summary["candidates"][name]["shape"]["main_primes"]["value"]
        for family, plan in block["families"].items():
            if plan["fits"]:
                result = "fits: output at level {} with {} of {} bits".format(
                    plan["output_level"]["value"],
                    plan["output_noise_bound_bits"]["value"],
                    plan["output_capacity_bits"]["value"],
                )
            else:
                result = "refused at instruction {} ({})".format(
                    plan["refused_at_instruction"]["value"], plan["refused_opcode"]
                )
            lines.append(
                "| `{}` ({}) | `{}` | {} | {} | {} |".format(
                    name,
                    have,
                    family,
                    result,
                    primes(plan["minimal_main_primes"]),
                    primes(plan["with_flooding_sanitization"][0]["minimal_main_primes"]),
                )
            )
    return "\n".join(lines)


def instruction_table(summary: dict) -> str:
    """Modelled and measured cost of one instruction of every opcode, as Markdown."""
    lowering = summary["tape_lowering"]["candidates"]
    measurements = summary["tape_instruction_measurements"]
    bounded_name, affine_name = RUN_CONFIGS[BOUNDED_TAPE_CONFIG][1], RUN_CONFIGS[AFFINE_TAPE_CONFIG][1]
    bounded_costs = lowering[bounded_name]["instruction_costs"]
    affine_costs = lowering[affine_name]["instruction_costs"]
    lines = [
        "| Instruction | Operations (bounded candidate) | Work units, affine candidate | Work units, bounded candidate"
        " | Measured, affine candidate | Measured, bounded candidate |",
        "| --- | --- | ---: | ---: | ---: | ---: |",
    ]

    def operations(work: dict) -> str:
        parts = []
        for field, singular in (
            ("plaintext_multiplications", "plaintext multiplication"),
            ("key_switches", "key switch"),
            ("multiplications", "ciphertext multiplication"),
            ("modulus_switches", "modulus switch"),
        ):
            value = work[field]["value"]
            if value:
                plural = singular + ("es" if singular.endswith("ch") else "s")
                parts.append(f"{value} {singular if value == 1 else plural}")
        return ", ".join(parts) if parts else "none charged"

    def measured_time(config: str, label: str) -> str:
        block = measurements[config]["instructions"].get(label)
        return "" if block is None else _milliseconds(block["wall_ns_per_call"]["value"])

    for label in list(OPCODES) + ["final zeroing mask"]:
        work = bounded_costs[label]
        affine_units = affine_costs[label]["work_units"]["value"] if label in affine_costs else None
        lines.append(
            "| {} | {} | {} | {:,} | {} | {} |".format(
                label,
                operations(work),
                "not admitted" if affine_units is None else f"{affine_units:,}",
                work["work_units"]["value"],
                measured_time(AFFINE_TAPE_CONFIG, label),
                measured_time(BOUNDED_TAPE_CONFIG, label),
            )
        )
    return "\n".join(lines)


def input_proof_table(summary: dict) -> str:
    """The projected input well-formedness relation of both encodings at N = 2^16, as Markdown."""
    relation = summary["proof_work_projection"]["input_relation"]
    sparse, batching = relation[SPARSE_CONFIG], relation[BATCHING_CONFIG]
    rows = (
        ("Mask and error coefficients range-checked", "secret_coefficients_range_checked"),
        ("Plaintext slots range-checked", "plaintext_slots_range_checked"),
        ("Plaintext coefficients fixed to zero by the encoding", "plaintext_coefficients_fixed_to_zero"),
        ("Butterflies of the slot transform", "slot_transform_butterflies"),
        ("Bits of the slot-transform modulus", "slot_transform_modulus_bits"),
        ("Ciphertext coefficient equations", "ciphertext_coefficient_equations"),
        ("Residue multiplications over the chain", "chain_residue_multiplications"),
        ("16-bit limb products", "limb_products"),
        ("Range-checked 16-bit limbs", "range_checked_limbs"),
        ("log2 of the rows at one multiplication per row", "log2_rows_at_one_multiplication_per_row"),
        ("Range-checked limbs that depend on the encoding", "encoding_specific_range_checked_limbs"),
        ("Their share of all range-checked limbs (parts per million)", "encoding_specific_share_ppm"),
    )
    lines = [
        "| Projected quantity of the input relation | F257 sparse, 22 primes | t = 786433, 25 primes | batching / sparse |",
        "| --- | ---: | ---: | ---: |",
    ]
    for label, key in rows:
        a, b = sparse[key]["value"], batching[key]["value"]
        ratio = "" if not a else f"{b / a:.2f}"
        lines.append("| {} | {:,} | {:,} | {} |".format(label, a, b, ratio))
    return "\n".join(lines)


def _cost_cell(entry: dict) -> str:
    """One attack as a table cell: its cost in bits, or why it has none."""
    if entry["status"] != "ok":
        return entry["status"].replace("_", " ")
    cost = entry["log2_cost"]
    return "infinite" if cost == "infinite" else f"{cost['value']:.1f}"


def _minimum_cell(verdict: dict) -> str:
    if "minimum_log2_cost" not in verdict:
        return "no attack has a cost"
    return "{:.1f} ({}, {})".format(
        verdict["minimum_log2_cost"]["value"],
        verdict["minimum_attack"],
        verdict["minimum_instance"].replace(":", ", m = ").replace("oo", "∞").replace("QP", "Q*P"),
    )


def _target_cell(verdict: dict) -> str:
    if "margin_bits" not in verdict:
        return "unknown"
    met = "met" if verdict["meets_design_target_on_the_attacks_with_a_cost"] else "**not met**"
    return f"{met} ({verdict['margin_bits']['value']:+.1f})"


def _attacks_with_a_cost(block: dict, of_attempted: bool = False) -> str:
    """How many attacks have a result, of all of them or of those the record attempted."""
    entries = []
    for instance in block["instances"].values():
        for model in instance["models"].values():
            entries.extend(model["attacks"].values())
        entries.extend(instance["attacks_without_a_cost_model"].values())
    if of_attempted:
        entries = [entry for entry in entries if entry["status"] != "not_attempted"]
    finished = sum(1 for entry in entries if entry["status"] == "ok")
    return f"{finished} of {len(entries)}"


def _profiles_in_listed_order(estimator: dict) -> list:
    """(name, block) of the estimated profiles, candidates first; a stored summary sorts its keys."""
    profiles = estimator.get("profiles", {})
    return [(name, profiles[name]) for name in estimated_profiles() if name in profiles]


def estimator_verdict_table(summary: dict) -> str:
    """The cheapest attack per profile and cost model against the design target, as Markdown."""
    estimator = summary["security_estimate"]["lattice_estimator"]
    lines = [
        "| Profile | Role | BDGL16 classical | ADPS16 classical | ADPS16 quantum"
        f" | {DESIGN_TARGET_BITS} bits under BDGL16 | {DESIGN_TARGET_BITS} bits under ADPS16"
        " | Sanity: core-SVP classical / BDGL16-style | Attacks with a result |",
        "| --- | --- | ---: | ---: | ---: | --- | --- | ---: | ---: |",
    ]
    for name, block in _profiles_in_listed_order(estimator):
        verdict = block["verdict"]
        comparison = block["core_svp_sanity_comparison"]
        sanity = " / ".join(
            f"{comparison[key]['sanity_bits']['value']}" if key in comparison else "unknown"
            for key in ("core_svp_classical", "bdgl16_style_classical")
        )
        lines.append(
            "| `{}` | {} | {} | {} | {} | {} | {} | {} | {} |".format(
                name,
                block["role"],
                _minimum_cell(verdict["BDGL16"]),
                _minimum_cell(verdict["ADPS16"]),
                _minimum_cell(verdict["ADPS16-quantum"]),
                _target_cell(verdict["BDGL16"]),
                _target_cell(verdict["ADPS16"]),
                sanity,
                _attacks_with_a_cost(block),
            )
        )
    return "\n".join(lines)


def estimator_attack_table(summary: dict) -> str:
    """Every attack on the largest modulus, with m = n and with unlimited samples, as Markdown."""
    estimator = summary["security_estimate"]["lattice_estimator"]
    lines = [
        "| Profile | Cost model | "
        + " | ".join(ESTIMATOR_ATTACK_NAMES[attack] for attack in ESTIMATOR_LATTICE_ATTACKS)
        + " | Cheapest on Q, m = n |",
        "| --- | --- | " + " | ".join("---:" for _ in ESTIMATOR_LATTICE_ATTACKS) + " | ---: |",
    ]
    for name, block in _profiles_in_listed_order(estimator):
        for model in ESTIMATOR_MODELS:
            cells = []
            for attack in ESTIMATOR_LATTICE_ATTACKS:
                pair = [
                    _cost_cell(block["instances"][instance]["models"][model]["attacks"][attack])
                    for instance in ("QP:n", "QP:oo")
                ]
                cells.append(pair[0] if pair[0] == pair[1] and not pair[0][0].isdigit() else " / ".join(pair))
            minimum = block["instances"]["Q:n"]["models"][model].get("minimum")
            cells.append(
                "{:.1f} ({})".format(minimum["log2_cost"]["value"], minimum["attack"]) if minimum else "no cost"
            )
            lines.append(f"| `{name}` | {model} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


def estimator_proposal_table(summary: dict) -> str:
    """The shapes outside the pinned list that the record estimates, as Markdown."""
    proposals = summary["security_estimate"]["lattice_estimator"].get("proposals", {})
    lines = [
        "| Shape (not pinned) | Differs from | BDGL16 classical | ADPS16 classical | ADPS16 quantum"
        f" | {DESIGN_TARGET_BITS} bits under BDGL16 | {DESIGN_TARGET_BITS} bits under ADPS16"
        " | Attacks with a result, of those run |",
        "| --- | --- | ---: | ---: | ---: | --- | --- | ---: |",
    ]
    for name, block in proposals.get("shapes", {}).items():
        varies = block.get("varies")
        shape = block["shape"]
        if varies is None:
            differs = "no candidate"
        elif varies["in"] == "main_primes":
            differs = "`{}`: {} main primes".format(varies["candidate"], shape["main_primes"]["value"])
        else:
            differs = "`{}`: N = 2^{}".format(varies["candidate"], shape["log_degree"]["value"])
        verdict = block["verdict"]
        lines.append(
            "| `{}` | {} | {} | {} | {} | {} | {} | {} |".format(
                name,
                differs,
                _minimum_cell(verdict["BDGL16"]),
                _minimum_cell(verdict["ADPS16"]),
                _minimum_cell(verdict["ADPS16-quantum"]),
                _target_cell(verdict["BDGL16"]),
                _target_cell(verdict["ADPS16"]),
                _attacks_with_a_cost(block, of_attempted=True),
            )
        )
    return "\n".join(lines)


def embedded_block(marker: str, table: str) -> str:
    return f"<!-- {marker}:begin (generated by scripts/fhe_bgv_cost_model.py --tables) -->\n{table}\n<!-- {marker}:end -->"


def embedded_tables(summary: dict) -> tuple:
    """(specification, marker, table) of every table this tool owns."""
    return (
        (COMPARISON_SPEC, COMPARISON_MARKER, comparison_table(summary)),
        (COMPARISON_SPEC, INSTRUCTION_MARKER, instruction_table(summary)),
        (COMPARISON_SPEC, INPUT_PROOF_MARKER, input_proof_table(summary)),
        (CANDIDATE_SPEC, CANDIDATE_MARKER, candidate_table(summary)),
        (CANDIDATE_SPEC, CLASS_FIT_MARKER, class_fit_table(summary)),
        (CANDIDATE_SPEC, ESTIMATOR_MARKER, estimator_verdict_table(summary)),
        (CANDIDATE_SPEC, ESTIMATOR_ATTACKS_MARKER, estimator_attack_table(summary)),
        (CANDIDATE_SPEC, ESTIMATOR_PROPOSALS_MARKER, estimator_proposal_table(summary)),
    )


def write_embedded_tables(summary: dict, root: Path = ROOT) -> None:
    """Replace each marked block of the specifications; a missing marker is an error."""
    for spec_path, marker, table in embedded_tables(summary):
        path = root / spec_path
        text = path.read_text()
        pattern = re.compile(rf"<!-- {re.escape(marker)}:begin .*?<!-- {re.escape(marker)}:end -->", re.S)
        if not pattern.search(text):
            raise SystemExit(f"{spec_path}: no {marker} block")
        path.write_text(pattern.sub(lambda _match: embedded_block(marker, table), text, count=1))


# ---------------------------------------------------------------------------
# Check
# ---------------------------------------------------------------------------

_RUST_TABLE = re.compile(r"const (F257_N1[46]_(?:MAIN|SPECIAL)_PRIMES): \[u64; \d+\] = \[(.*?)\];", re.S)
_RUST_CONSTANT = re.compile(r"^pub const (\w+): (?:u16|u32|u64|usize) = ([0-9_]+);", re.M)

# Constants of the R.0 contract this model restates, by their names in CLASS_SOURCE.
CLASS_CONSTANTS = {
    "RAM_LFE_V1_PLAINTEXT_MODULUS": PLAINTEXT_MODULUS,
    "RAM_LFE_V1_REGISTERS": REGISTERS,
    "RAM_LFE_V1_STATE_LANES": STATE_LANES,
    "RAM_LFE_V1_INPUT_SLOTS": INPUT_SLOTS,
    "RAM_LFE_V1_MAX_INSTRUCTIONS": MAX_INSTRUCTIONS,
    "RAM_LFE_V1_MAX_OUTPUTS": MAX_OUTPUTS,
    "RAM_LFE_V1_BOUNDED_MAX_RANK": BOUNDED_MAX_RANK,
    "RAM_LFE_V1_REFRESH_MAX_RANK_BETWEEN_REFRESHES": REFRESH_MAX_RANK_BETWEEN_REFRESHES,
    "RAM_LFE_V1_REFRESH_MAX_REFRESHES": REFRESH_MAX_REFRESHES,
    "RAM_LFE_V1_SELECT_CONDITION_RANK": SELECT_MULTIPLICATIONS,
    "RAM_LFE_V1_SELECT_BRANCH_RANK": SELECT_BRANCH_RANK,
}
# Constants of the costing harness, by their names in HARNESS_SOURCE.
HARNESS_CONSTANTS = {
    "REGISTERS": REGISTERS,
    "STATE_LANES": STATE_LANES,
    "INPUT_SLOTS": INPUT_SLOTS,
    "MAX_INSTRUCTIONS": MAX_INSTRUCTIONS,
    "MAX_OUTPUTS": MAX_OUTPUTS,
    "BOUNDED_MAX_RANK": BOUNDED_MAX_RANK,
    "SELECT_SQUARINGS": SELECT_SQUARINGS,
}


def rust_prime_tables(root: Path) -> dict:
    text = (root / PROFILE_SOURCE).read_text()
    tables = {}
    for name, body in _RUST_TABLE.findall(text):
        tables[name] = [int(item.replace("_", "")) for item in re.findall(r"[0-9_]+", body) if item.strip("_")]
    return tables


def rust_constants(text: str) -> dict:
    """Every `pub const NAME: <integer type> = <literal>;` at the start of a line."""
    return {name: int(value.replace("_", "")) for name, value in _RUST_CONSTANT.findall(text)}


def class_descriptor(text: str) -> dict:
    """Opcode names by tag and the opcode set and limits of each class, from the semantics descriptor."""
    opcodes = {int(tag): name for tag, name in re.findall(r"^opcode=(\d+):(\w+)\(", text, re.M)}
    classes = {}
    for name, tags, rank, refreshes in re.findall(
        r"^class=([\w.]+);opcodes=([\d,]+);max-rank=(\d+);max-refreshes=(\d+)$", text, re.M
    ):
        classes[name] = (tuple(int(tag) for tag in tags.split(",")), int(rank), int(refreshes))
    return {"opcodes": opcodes, "classes": classes}


def source_problems(root: Path) -> list:
    """Disagreements between the constants of this model and the Rust sources that own them."""
    problems = []
    class_text = (root / CLASS_SOURCE).read_text()
    constants = rust_constants(class_text)
    for name, expected in CLASS_CONSTANTS.items():
        if constants.get(name) != expected:
            problems.append(f"{CLASS_SOURCE}: {name} is {constants.get(name)}, this model uses {expected}")
    descriptor = class_descriptor(class_text)
    if descriptor["opcodes"] != dict(enumerate(OPCODES)):
        problems.append(f"{CLASS_SOURCE}: the opcode lines of the semantics descriptor differ from this model")
    every = tuple(range(len(OPCODES)))
    expected_classes = {
        "affine.v1": (AFFINE_OPCODES, 0, 0),
        "bounded.v1": (every, BOUNDED_MAX_RANK, 0),
        "refresh.v1": (every, REFRESH_MAX_RANK_BETWEEN_REFRESHES, REFRESH_MAX_REFRESHES),
    }
    if descriptor["classes"] != expected_classes:
        problems.append(f"{CLASS_SOURCE}: the class lines of the semantics descriptor differ from this model")
    harness_text = (root / HARNESS_SOURCE).read_text()
    harness = rust_constants(harness_text)
    for name, expected in HARNESS_CONSTANTS.items():
        if harness.get(name) != expected:
            problems.append(f"{HARNESS_SOURCE}: {name} is {harness.get(name)}, this model uses {expected}")
    names = re.search(r"pub const OPCODE_NAMES: \[&str; 11\] = \[(.*?)\];", harness_text, re.S)
    if names is None or tuple(re.findall(r'"(\w+)"', names.group(1))) != OPCODES:
        problems.append(f"{HARNESS_SOURCE}: OPCODE_NAMES differs from this model")
    if rust_constants((root / COINS_SOURCE).read_text()).get("ERROR_ETA") != ERROR_ETA:
        problems.append(f"{COINS_SOURCE}: ERROR_ETA differs from this model")
    if rust_constants((root / CHAIN_SOURCE).read_text()).get("MAX_BASIS_PRIMES") != MAX_BASIS_PRIMES:
        problems.append(f"{CHAIN_SOURCE}: MAX_BASIS_PRIMES differs from this model")
    return problems


def unclassified_numbers(value: Any, path: str = "") -> list:
    """Paths of numbers that are not the `value` of a classified entry."""
    problems = []
    if isinstance(value, dict):
        if "value" in value and "class" in value:
            if value["class"] not in CLASSES:
                problems.append(f"{path}: class {value['class']!r}")
            if "unit" not in value:
                problems.append(f"{path}: no unit")
            for key, item in value.items():
                if key not in ("value", "class", "unit", "basis"):
                    problems.extend(unclassified_numbers(item, f"{path}/{key}"))
            return problems
        for key, item in value.items():
            problems.extend(unclassified_numbers(item, f"{path}/{key}"))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            problems.extend(unclassified_numbers(item, f"{path}[{index}]"))
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        problems.append(f"{path}: bare number {value}")
    return problems


def equal_workload_run_problems(run: dict, p: Profile) -> list:
    """Reported geometry, sizes, model values and operation counts of one equal-workload run."""
    problems = []
    config = run["config"]
    geometry = {key: item["value"] for key, item in run["geometry"].items()}
    expected_geometry = {
        "ring_degree": p.degree,
        "main_primes": p.top + 1,
        "special_primes": len(p.special),
        "key_switch_digits": p.digit_count(),
        "scalar_slots": p.slots(),
        "slot_mask_l1_norm": p.mask_l1(),
        "modulus_bits": p.modulus(p.top).bit_length(),
        "special_modulus_bits": p.special_product.bit_length(),
        "fresh_noise_bound_bits": p.fresh_noise().bit_length(),
        "key_switch_noise_bound_bits": p.key_switch_noise(p.top).bit_length(),
    }
    if geometry != expected_geometry:
        problems.append(f"{config}: reported geometry differs from the model")
    sizes = {key: item["value"] for key, item in run["sizes"].items()}
    plan = plan_equal_workload(p)
    expected_sizes = {
        "public_key_frame": p.public_key_bytes(),
        "switching_key_frame": p.switching_key_bytes(),
        "evaluation_keys_frame": p.evaluation_key_bytes(p.broadcast_steps()),
        "input_ciphertext_frame": p.ciphertext_bytes(p.top),
        "output_ciphertext_frame": p.ciphertext_bytes(plan.steps[-1]["level"]),
    }
    if sizes != expected_sizes:
        problems.append(f"{config}: reported sizes differ from the model")
    declared = {key: item["value"] for key, item in run["declared_model_values"].items()}
    expected_declared = {
        "model.multiplication_units_top_level": p.multiplication_units(p.top),
        "model.key_switch_units_top_level": p.key_switch_units(p.top),
        "model.plaintext_multiplication_units_top_level": p.plaintext_multiplication_units(p.top),
        "model.key_switch_scratch_bytes_top_level": p.key_switch_scratch_bytes(p.top),
    }
    if declared != expected_declared:
        problems.append(f"{config}: declared model values differ from the model")
    # Operation counts the workload reported equal the plan.
    reported = {"multiplications": 0, "key_switches": 0, "plaintext_multiplications": 0, "modulus_switches": 0}
    labels = {
        "ciphertext_multiplications": "multiplications",
        "key_switches": "key_switches",
        "plaintext_multiplications": "plaintext_multiplications",
        "modulus_switches": "modulus_switches",
    }
    for block in run["phases"].values():
        for label, key in labels.items():
            if label in block:
                reported[key] += block[label]["value"]
    if reported != plan.counts:
        problems.append(f"{config}: reported operation counts {reported} differ from the plan {plan.counts}")
    # The public noise bounds the evaluator reported at four points equal the plan's.
    planned_bits = {step["step"]: step["noise_bound_bits"] for step in plan.steps}
    for phase, label, step in (
        ("load_modulus_switch", "noise_bound_bits", "load_input"),
        ("equality_exponentiation", "noise_bound_bits", "equality_exponentiation"),
        ("select_multiplication", "noise_bound_bits", "select_eq_zero"),
        ("unused_output_zeroing", "noise_bound_bits", "output"),
        ("unused_output_zeroing", "capacity_bits", "final_capacity_bits"),
    ):
        if run["phases"][phase].get(label, {}).get("value") != planned_bits[step]:
            problems.append(f"{config}: {label} reported after {phase} differs from the plan")
    return problems


TAPE_WORK_LABELS = (
    "plaintext_multiplications",
    "key_switches",
    "ciphertext_multiplications",
    "modulus_switches",
    "model_work_units",
)


def tape_run_problems(run: dict, name: str, shape: tuple) -> list:
    """What the encrypted harness reported for one instruction-profile run against the shape run."""
    problems = []
    config = run["config"]
    p = profile(name, shape)
    tape = instruction_profile(name)
    plan = cached_plan(shape, tape)

    def reported(block: dict) -> list:
        return [block[label]["value"] if label in block else 0 for label in TAPE_WORK_LABELS]

    for tag, opcode in enumerate(OPCODES):
        count = plan["instructions"][tag]
        block = run["instructions"].get(opcode)
        if (block is None) != (count == 0):
            problems.append(f"{config}: {opcode} phases differ from the profile tape")
        elif block is not None:
            if block["calls"]["value"] != count:
                problems.append(f"{config}: {opcode} ran {block['calls']['value']} times, the tape has {count}")
            if reported(block) != plan["by_opcode"][tag]:
                problems.append(f"{config}: {opcode} work differs from the shape run")
    final = run["final_zeroing_mask"]
    if reported(final) != plan["by_opcode"][FINAL_MASK]:
        problems.append(f"{config}: the work of the final mask differs from the shape run")
    expected_final = {
        "noise_bound_bits": plan["bound"].bit_length(),
        "capacity_bits": plan["capacity"].bit_length(),
        "output_level": plan["level"],
    }
    for label, expected in expected_final.items():
        # A level of zero is not reported: the recorder keeps non-zero work only.
        if final.get(label, {"value": 0})["value"] != expected:
            problems.append(f"{config}: {label} of the output differs from the shape run")
    declared = {key: item["value"] for key, item in run["declared_model_values"].items()}
    expected_declared = {
        "model.peak_persistent_ciphertext_bytes": plan["peak_persistent_bytes"],
        "model.peak_working_bytes": plan["peak_working_bytes"],
        "model.tape_work_units": plan["total"][UNITS],
    }
    if declared != expected_declared:
        problems.append(f"{config}: declared model values differ from the shape run")
    sizes = {key: item["value"] for key, item in run["sizes"].items()}
    expected_sizes = {
        "evaluation_keys_frame": p.evaluation_key_bytes(p.broadcast_steps()),
        "input_ciphertext_frame": p.ciphertext_bytes(p.top),
        "output_ciphertext_frame": p.ciphertext_bytes(plan["level"]),
    }
    if sizes != expected_sizes:
        problems.append(f"{config}: reported sizes differ from the model")
    geometry = {key: item["value"] for key, item in run["geometry"].items()}
    expected_geometry = {
        "ring_degree": p.degree,
        "main_primes": p.top + 1,
        "special_primes": len(p.special),
        "scalar_slots": p.slots(),
    }
    if geometry != expected_geometry:
        problems.append(f"{config}: reported geometry differs from the model")
    return problems


def check_summary(summary: dict, root: Path = ROOT) -> list:
    problems = []
    if summary.get("schema") != SCHEMA:
        problems.append("schema")
    problems.extend(unclassified_numbers(summary))
    # The constants this model restates are those of the Rust sources that own them.
    problems.extend(source_problems(root))
    # The pinned Rust tables follow the first-prime rule this model uses.
    tables = rust_prime_tables(root)
    expected_tables = {
        "F257_N14_MAIN_PRIMES": profile("bgv.f257.n14.q6x50.p2x60", CANDIDATES["bgv.f257.n14.q6x50.p2x60"]).main,
        "F257_N14_SPECIAL_PRIMES": profile("bgv.f257.n14.q6x50.p2x60", CANDIDATES["bgv.f257.n14.q6x50.p2x60"]).special,
        "F257_N16_MAIN_PRIMES": profile("bgv.f257.n16.q32x50.p2x60", CANDIDATES["bgv.f257.n16.q32x50.p2x60"]).main,
        "F257_N16_SPECIAL_PRIMES": profile("bgv.f257.n16.q32x50.p2x60", CANDIDATES["bgv.f257.n16.q32x50.p2x60"]).special,
    }
    for name, expected in expected_tables.items():
        if tables.get(name) != expected:
            problems.append(f"{PROFILE_SOURCE}: {name} differs from the first-prime rule")
    if not (root / ESTIMATOR_SCRIPT).is_file():
        problems.append(f"{ESTIMATOR_SCRIPT} is missing")
    # The identities the Rust test pins are those of the Python reference.
    vectors_test = (root / VECTORS_TEST).read_text()
    for name, shape in CANDIDATES.items():
        if f'"{profile_identity(shape)}"' not in vectors_test:
            problems.append(f"{VECTORS_TEST}: the identity of {name} is not pinned")
    runs = summary.get("runs", [])
    known = [run for run in runs if run.get("config") in RUN_CONFIGS]
    for run in runs:
        if run.get("config") not in RUN_CONFIGS:
            problems.append(f"run of unknown config {run.get('config')!r}")
    for config in sorted(set(RUN_CONFIGS) - {run["config"] for run in known}):
        problems.append(f"no run of {config}")
    for run in known:
        config = run["config"]
        kind, name, shape = RUN_CONFIGS[config]
        if run["run"].get("verdict") != "accepted":
            problems.append(f"{config}: run not accepted")
        if run.get("kind") != kind:
            problems.append(f"{config}: the run is not of the {kind} workload")
            continue
        if kind == "equal_workload":
            problems.extend(equal_workload_run_problems(run, profile(name, shape)))
        else:
            problems.extend(tape_run_problems(run, name, shape))
        unattributed = run["process"]["root_unattributed_wall_ns"]["value"]
        if unattributed * 100 > run["process"]["root_wall_ns"]["value"]:
            problems.append(f"{config}: more than 1% of the wall time is unattributed")
    if problems:
        return problems
    # Every derived block equals its recomputation from the parameters and the measured runs.
    for key, expected in derived_blocks(runs).items():
        if summary.get(key) != expected:
            problems.append(f"{key}: differs from its recomputation")
    # The estimator record is the output of the script as it stands, for the moduli of this model.
    problems.extend(estimator_record_problems(root))
    if problems:
        return problems
    frame = summary_frame(runs, summary.get("host"), root)
    for key in ("classification", "measurement_notes", "scope", "generator", "task"):
        if summary.get(key) != frame[key]:
            problems.append(f"{key}: differs from the generator")
    # Every estimator number of the summary is the restatement of the tracked output record.
    if summary.get("security_estimate") != frame["security_estimate"]:
        problems.append(f"security_estimate: differs from its recomputation from {ESTIMATOR_OUTPUT}")
    if problems:
        return problems
    # The tables the specifications embed and the view the Rust test reads are rendered from this summary.
    for spec_path, marker, table in embedded_tables(summary):
        if embedded_block(marker, table) not in (root / spec_path).read_text():
            problems.append(f"{spec_path}: the {marker} table differs from the summary")
    vectors = root / MODEL_VECTORS_PATH
    if not vectors.is_file() or vectors.read_text() != model_vectors_text(summary):
        problems.append(f"{MODEL_VECTORS_PATH}: differs from the view of the summary")
    return problems


def print_plans() -> None:
    for name, shape in list(CANDIDATES.items()) + [value for value in MEASURED_CONFIGS.values()]:
        p = profile(name, shape)
        sanity = security_sanity(p)
        print(
            f"{name}: N=2^{p.log_degree} t={p.t} log2(QP)={p.total_modulus_bits():.1f}"
            f" slots={p.slots()} mask_l1={p.mask_l1()} fresh={p.fresh_noise().bit_length()}b"
            f" ks={p.key_switch_noise(p.top).bit_length()}b"
            f" core-SVP beta={sanity['bkz_block_size']['value']}"
            f" classical={sanity['core_svp_classical_bits']['value']}"
            f" quantum={sanity['core_svp_quantum_bits']['value']}"
            f" bdgl16-style={sanity['bdgl16_style_classical_bits']['value']}"
        )
    for config, (name, shape) in MEASURED_CONFIGS.items():
        print(config, "minimal main primes for the equal workload:", minimal_main_primes(shape, plan_equal_workload))
    for name, shape in CANDIDATES.items():
        for family in candidate_families(name):
            plan = cached_plan(shape, FAMILIES[family][2])
            verdict = (
                f"fits at level {plan['level']} with {plan['bound'].bit_length()} of {plan['capacity'].bit_length()} bits"
                if plan["fits"]
                else f"refused at instruction {plan['instruction']} ({opcode_label(plan['tag'])})"
            )
            print(f"{name} {family}: {verdict}; needs {tape_minimal_main_primes(shape, FAMILIES[family][2])} main primes")


def write_outputs(summary: dict, root: Path = ROOT) -> None:
    """The tracked summary, the view the Rust test reads and the tables of the specifications."""
    text = render(summary)
    (root / SUMMARY_PATH).write_text(text)
    # The view and the tables follow the key order of the file, which is what a check reads.
    stored = json.loads(text)
    (root / MODEL_VECTORS_PATH).write_text(model_vectors_text(stored))
    write_embedded_tables(stored, root)


def main(argv: list) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--build", nargs="+", metavar="RUN_DIR", help="accepted harness run directories")
    parser.add_argument("--manifest-sha256", nargs="+", metavar="SHA256",
                        help="with --build: one externally retained manifest pin per directory")
    parser.add_argument(
        "--rederive",
        action="store_true",
        help="recompute every derived block from the measured runs the tracked summary already holds",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="with --build or --rederive: replace the tracked summary, the model vectors and the embedded tables",
    )
    parser.add_argument("--plan", action="store_true", help="print noise plans, tape plans and sanity numbers")
    parser.add_argument("--tables", action="store_true", help="print the Markdown tables the specifications embed")
    parser.add_argument("--summary", default=str(ROOT / SUMMARY_PATH), help="summary file to check")
    arguments = parser.parse_args(argv)
    if bool(arguments.build) != bool(arguments.manifest_sha256):
        parser.error("--build requires --manifest-sha256; pins are only valid with --build")
    if arguments.plan:
        print_plans()
        return 0
    if arguments.tables:
        summary = json.loads(Path(arguments.summary).read_text())
        for _, marker, table in embedded_tables(summary):
            print(embedded_block(marker, table))
            print()
        return 0
    if arguments.build or arguments.rederive:
        if arguments.build:
            try:
                summary = build_summary([Path(item) for item in arguments.build],
                                        manifest_sha256=arguments.manifest_sha256)
            except (HARNESS.HarnessRefusal, ValueError) as error:
                print(str(error), file=sys.stderr)
                return 1
        else:
            summary = rederive(json.loads(Path(arguments.summary).read_text()))
        if arguments.write:
            write_outputs(summary)
        else:
            sys.stdout.write(render(summary))
        return 0
    path = Path(arguments.summary)
    if not path.is_file():
        print(f"{path} is missing", file=sys.stderr)
        return 1
    problems = check_summary(json.loads(path.read_text()))
    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        return 1
    print(f"{SUMMARY_PATH}: consistent with the source tree and with its own measured values")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
