#!/usr/bin/env python3
"""Evaluate the specified B6 conditional composition terms, never qualification.

Prerequisites: Python 3.11+ and its standard library. No environment variables,
repository inputs, network access, builds or file writes are used. The default
T=2^44 and Q_all=2^64 are illustrative ceilings, not accepted resource premises.
Output is deterministic JSON; --require-qualified always fails with exit 2.

Exact fractions determine every component and comparison. A fixed decimal-grid
integer square root encloses the known-term formula, not an adversary advantage.
Decimal strings are approximate display only. Initial programming, AES advantage
and complete driver resources remain unknown. See the separately maintained
specs/parliament_ballot_b6_conditional_composition.md for the conditional argument.
"""

from __future__ import annotations

import argparse
from decimal import Context, Decimal, ROUND_HALF_EVEN, localcontext
from fractions import Fraction
from math import isqrt
import sys
import json


DEFAULT_INVOCATIONS = 1 << 44
DEFAULT_QUERIES = 1 << 64
SQRT_DECIMAL_PLACES = 120
SQRT_SCALE = 10**SQRT_DECIMAL_PLACES
MATERIAL_COEFFICIENT = 2_892_601
GATES = 704
ONE = Fraction(1)


def nonnegative_count(value: int, name: str) -> int:
    """Accept actual nonnegative integers, excluding bool and coerced values."""
    if type(value) is not int or value < 0:
        raise ValueError(f"{name} must be a nonnegative integer (not bool)")
    return value


def sqrt_enclosure(value: Fraction) -> tuple[Fraction, Fraction]:
    """Enclose sqrt(value) rigorously on the fixed 120-place rational grid."""
    if not isinstance(value, Fraction) or value < 0:
        raise ValueError("square-root input must be a nonnegative Fraction")
    scaled_numerator = value.numerator * SQRT_SCALE**2
    floor_root = isqrt(scaled_numerator // value.denominator)
    lower = Fraction(floor_root, SQRT_SCALE)
    exact = floor_root**2 * value.denominator == scaled_numerator
    upper = lower if exact else Fraction(floor_root + 1, SQRT_SCALE)
    return lower, upper


def calculate_terms(
    invocations: int = DEFAULT_INVOCATIONS, queries: int = DEFAULT_QUERIES
) -> dict[str, Fraction | tuple[Fraction, Fraction]]:
    """Return exact known components and a formula enclosure, with no total claim."""
    t = nonnegative_count(invocations, "invocations")
    q = nonnegative_count(queries, "queries")
    material = Fraction(t * MATERIAL_COEFFICIENT, 2**128)
    own_label = Fraction(t, 2**256)
    h5_queries = 2 * q + 2 * t
    sqrt_lower, sqrt_upper = sqrt_enclosure(Fraction(h5_queries, 2**512))
    h5_linear = Fraction(h5_queries, 2**513)
    h5 = tuple(GATES * t * (endpoint + h5_linear)
               for endpoint in (sqrt_lower, sqrt_upper))
    deletion_unclipped = (
        Fraction(2 * (q + GATES * t), 2**128)
        + Fraction(t * (t - 1) // 2, 2**256)
    )
    deletion = min(ONE, deletion_unclipped)
    known = tuple(material + endpoint + own_label + deletion for endpoint in h5)
    return {
        "material_switching": material,
        "h5_reprogramming": h5,
        "own_label": own_label,
        "deletion_unclipped": deletion_unclipped,
        "deletion": deletion,
        "known_unclipped": known,
        "known_clipped_at_one": tuple(min(ONE, endpoint) for endpoint in known),
    }


def fraction_record(value: Fraction) -> dict[str, str]:
    """Serialize exact integers as strings; the decimal is display-only."""
    with localcontext(Context(prec=40, rounding=ROUND_HALF_EVEN)):
        approximate = format(Decimal(value.numerator) / Decimal(value.denominator), ".24E")
    return {
        "numerator": str(value.numerator),
        "denominator": str(value.denominator),
        "approximate_decimal": approximate,
    }


def interval_record(interval: tuple[Fraction, Fraction]) -> dict[str, dict[str, str]]:
    """Serialize the lower/upper enclosure of a mathematical formula value."""
    return {"lower": fraction_record(interval[0]), "upper": fraction_record(interval[1])}


def build_report(
    invocations: int = DEFAULT_INVOCATIONS, queries: int = DEFAULT_QUERIES
) -> dict:
    """Describe the known contribution and retain all unresolved fields as null."""
    terms = calculate_terms(invocations, queries)
    return {
        "schema": "parliament-ballot-conditional-composition-v1",
        "scope": "Conditional formula evaluation only; not a complete security bound.",
        "inputs": {"T": str(invocations), "Q_all": str(queries)},
        "input_scope": {
            "T": "Valid proving invocations, including exhaustion, jointly across roles and rows.",
            "Q_all": (
                "All lifetime non-prover combined backend evaluations, including preprocessing, "
                "interleaving, verification, diagnostics, relevant invalid-request checks and "
                "post-proof access; count actual lookup/unlookup calls."
            ),
            "defaults": "Illustrative ceilings, not accepted resource premises.",
        },
        "arithmetic": {
            "exact_integer_encoding": "Decimal strings in inputs and fraction records.",
            "sqrt_enclosure_decimal_places": SQRT_DECIMAL_PLACES,
            "decimal_display_is_approximate": True,
        },
        "components": {
            "material_switching": fraction_record(terms["material_switching"]),
            "h5_reprogramming": interval_record(terms["h5_reprogramming"]),
            "own_label": fraction_record(terms["own_label"]),
            "deletion": {
                "unclipped": fraction_record(terms["deletion_unclipped"]),
                "clipped_at_one": fraction_record(terms["deletion"]),
            },
        },
        "known_contribution": {
            "interval_target": (
                "The stated known-term formula K, not adversary advantage. Its lower endpoint "
                "is not a security lower bound or an attack. K uses the clipped deletion term."
            ),
            "unclipped": interval_record(terms["known_unclipped"]),
            "clipped_at_one": interval_record(terms["known_clipped_at_one"]),
        },
        "initial_programming_bound": None,
        "aes_advantage_sum": None,
        "full_driver_resources": None,
        "qualified": False,
        "limitations": [
            "The common experiment, chosen-input AES/quantum-oracle premises and reductions "
            "remain conditional and need independent acceptance.",
            "The real-prover entry bound, AES advantages and full driver resource vectors "
            "are not supplied by this calculation.",
            "Neither K nor min(1,K) is a complete security bound; production remains gated.",
        ],
    }


def decimal_count(text: str) -> int:
    """Parse unsigned decimal CLI counts without coercing floats or booleans."""
    if not text or not text.isascii() or not text.isdecimal():
        raise argparse.ArgumentTypeError("expected a nonnegative decimal integer")
    try:
        return int(text)
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from error


def main(argv: list[str] | None = None) -> int:
    """Print deterministic JSON; a request for qualification always exits 2."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--invocations", type=decimal_count, default=DEFAULT_INVOCATIONS,
        help="T: valid invocations, including exhaustion, across all roles/rows (default: 2^44).",
    )
    parser.add_argument(
        "--queries", type=decimal_count, default=DEFAULT_QUERIES,
        help="Q_all: lifetime non-prover backend calls, including verifier/diagnostic/invalid "
             "checks (default: 2^64).",
    )
    parser.add_argument("--json", action="store_true", help="Emit deterministic JSON (the default and sole format).")
    parser.add_argument("--require-qualified", action="store_true", help="Always exit 2: unresolved premises prohibit qualification.")
    args = parser.parse_args(argv)
    print(json.dumps(build_report(args.invocations, args.queries), indent=2, sort_keys=True, allow_nan=False))
    if args.require_qualified:
        print("Not qualified: entry, AES advantages, full resources and premise acceptance remain unresolved.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
