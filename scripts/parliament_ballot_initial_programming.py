#!/usr/bin/env python3
"""Evaluate the conditional initial-programming formula and known composition.

Prerequisites: Python 3.11+, its standard library, and the unchanged sibling
parliament_ballot_conditional_composition.py. No environment variables, network,
builds or file writes are used. Default T=2^44 and Q_all=2^64 are illustrative
ceilings. The CLI emits deterministic JSON; --require-qualified always exits 2.

This is arithmetic for a conditional initial-programming lemma, not a proof of
its hypotheses or a complete security bound. AES advantages and full reduction
resources remain unknown. Exact fractions and integer square roots enclose the
formula; decimal strings are display-only. Entry square roots have a relative
400-bit enclosure, including the very small challenge-2 term. Post-entry K uses
the unchanged sibling helper's fixed 120-decimal-place enclosure.
"""

from __future__ import annotations

import argparse
from fractions import Fraction
import json
from math import isqrt
import sys

import parliament_ballot_conditional_composition as composition


MAX_TRIALS = 1 << 20
SQRT_RELATIVE_BITS = 400
ONE = Fraction(1)


def relative_sqrt_enclosure(value: Fraction) -> tuple[Fraction, Fraction]:
    """Enclose sqrt(x), with width <= 2^-400 sqrt(x), using integers only."""
    if not isinstance(value, Fraction) or value < 0:
        raise ValueError("square-root input must be a nonnegative Fraction")
    if value == 0:
        return Fraction(0), Fraction(0)
    numerator, denominator = value.numerator, value.denominator
    # bit_length gives either floor(log2(x)) or one more; compare exactly.
    exponent = numerator.bit_length() - denominator.bit_length()
    if exponent >= 0:
        if numerator < denominator << exponent:
            exponent -= 1
    elif numerator << -exponent < denominator:
        exponent -= 1
    # sqrt(x) >= 2^floor(exponent/2). Thus this grid's width is at most
    # 2^-400 sqrt(x), including when x is far smaller than a fixed grid unit.
    bits = max(0, SQRT_RELATIVE_BITS - exponent // 2)
    scale = 1 << bits
    scaled_numerator = numerator << (2 * bits)
    floor_root = isqrt(scaled_numerator // denominator)
    lower = Fraction(floor_root, scale)
    exact = floor_root**2 * denominator == scaled_numerator
    upper = lower if exact else Fraction(floor_root + 1, scale)
    return lower, upper


def calculate_terms(
    invocations: int = composition.DEFAULT_INVOCATIONS,
    queries: int = composition.DEFAULT_QUERIES,
) -> dict:
    """Calculate conditional entry and combined known formulas, without AES."""
    t = composition.nonnegative_count(invocations, "invocations")
    q = composition.nonnegative_count(queries, "queries")
    qhat = 2 * q + t
    components = {}
    for name, entropy_bits, repeats in (
        ("challenge_1", 256, t),
        ("challenge_2", 2112, t),
        ("challenge_3", 832, t * MAX_TRIALS),
    ):
        probability_product = Fraction(qhat, 1 << entropy_bits)
        lower, upper = relative_sqrt_enclosure(probability_product)
        components[name] = tuple(
            repeats * (endpoint + probability_product / 2)
            for endpoint in (lower, upper)
        )
    entry = tuple(sum((value[index] for value in components.values()), Fraction(0))
                  for index in (0, 1))
    entry_clipped = tuple(min(ONE, endpoint) for endpoint in entry)
    post_entry = composition.calculate_terms(t, q)["known_unclipped"]
    combined = tuple(entry_clipped[index] + post_entry[index] for index in (0, 1))
    return {
        "qhat": qhat,
        "components": components,
        "entry_unclipped": entry,
        "entry_clipped_at_one": entry_clipped,
        "post_entry_K": post_entry,
        "combined_known_unclipped": combined,
        "combined_known_clipped_at_one": tuple(min(ONE, endpoint) for endpoint in combined),
    }


def build_report(
    invocations: int = composition.DEFAULT_INVOCATIONS,
    queries: int = composition.DEFAULT_QUERIES,
) -> dict:
    """Report conditional formula enclosures and explicit qualification gaps."""
    terms = calculate_terms(invocations, queries)
    return {
        "schema": "parliament-ballot-initial-programming-v1",
        "scope": (
            "Arithmetic under the conditional initial-programming lemma and post-entry "
            "composition premises; not a complete security bound or proof of those premises."
        ),
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
            "entry_sqrt_relative_error_bits": SQRT_RELATIVE_BITS,
            "entry_sqrt_guarantee": "Enclosure width <= 2^-400 times the exact square root.",
            "post_entry_sqrt_decimal_places": composition.SQRT_DECIMAL_PLACES,
            "decimal_display_is_approximate": True,
        },
        "conditional_initial_programming": {
            "query_ceiling_qhat": str(terms["qhat"]),
            "query_ceiling_formula": "2*Q_all + T",
            "counter_cap_M": str(MAX_TRIALS),
            "formula": "T*F(qhat,2^-256) + T*F(qhat,2^-2112) + T*M*F(qhat,2^-832)",
            "F": "sqrt(q*p) + q*p/2",
            "components": {name: composition.interval_record(value)
                           for name, value in terms["components"].items()},
            "unclipped": composition.interval_record(terms["entry_unclipped"]),
            "clipped_at_one": composition.interval_record(terms["entry_clipped_at_one"]),
        },
        "post_entry_K": composition.interval_record(terms["post_entry_K"]),
        "combined_known_contribution": {
            "formula": "min(1, conditional entry formula) + K",
            "interval_target": (
                "The stated known formula value, not adversary advantage. Its lower endpoint "
                "is not a security lower bound or an attack. K is not clipped before addition."
            ),
            "unclipped": composition.interval_record(terms["combined_known_unclipped"]),
            "clipped_at_one": composition.interval_record(terms["combined_known_clipped_at_one"]),
        },
        "aes_advantage_sum": None,
        "full_driver_resources": None,
        "qualified": False,
        "limitations": [
            "Initial-programming bounds are conditional on the common experiment, samplers, "
            "query dispatch and adaptive reprogramming premises; this helper does not prove them.",
            "The post-entry formula inherits the chosen-input AES/quantum-oracle premises "
            "and the sibling composition's other hypotheses.",
            "AES advantages, full reduction resources and independent premise acceptance "
            "remain unresolved; neither reported known sum is a complete security bound.",
            "Production remains gated.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    """Emit deterministic JSON and always refuse requested qualification."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--invocations", type=composition.decimal_count, default=composition.DEFAULT_INVOCATIONS,
        help="T: valid invocations, including exhaustion, across roles/rows (default: 2^44).",
    )
    parser.add_argument(
        "--queries", type=composition.decimal_count, default=composition.DEFAULT_QUERIES,
        help="Q_all: lifetime non-prover backend calls, including verifier/diagnostic/invalid "
             "checks (default: 2^64).",
    )
    parser.add_argument("--json", action="store_true", help="Emit deterministic JSON (the default and sole format).")
    parser.add_argument("--require-qualified", action="store_true", help="Always exit 2: unresolved premises prohibit qualification.")
    args = parser.parse_args(argv)
    print(json.dumps(build_report(args.invocations, args.queries), indent=2, sort_keys=True, allow_nan=False))
    if args.require_qualified:
        print("Not qualified: conditional premises, AES advantages, full resources and independent acceptance remain unresolved.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
