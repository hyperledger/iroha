#!/usr/bin/env python3
"""Recompute the conditional Parliament B6 security ledger without certifying it.

Requires Python 3.11+ and only its standard library. No environment variables,
network, build products or repository paths are required. The default is read
only; --json emits a deterministic report. --require-qualified fails closed
because primitive bounds, reduction review and resource costs remain missing.
See specs/parliament_ballot_b6_security_review.md for assumptions and sources.
"""

from __future__ import annotations

import argparse
from decimal import Decimal, localcontext
from fractions import Fraction
import json
from math import prod
from typing import Callable


PRECISION = 160
T = 1 << 44
U = 1 << 34
J = 1 << 24
Q_ADVERSARY = 1 << 64
Q_NOMINAL = 1 << 77
COUNTERS = 1 << 20
EXPECTED_SEED_NUMERATOR = (
    100394214806767952210445323089436363695775791427601419753509949431295431340384
)
DIMENSIONS = {"registration": (35840, 72576, 35920), "vote": (53504, 108931, 53584)}


def pow2(exponent: int) -> Fraction:
    """Return an exact power of two, including negative exponents."""
    return Fraction(1 << exponent) if exponent >= 0 else Fraction(1, 1 << -exponent)


def dec(value: int | Fraction | Decimal) -> Decimal:
    """Convert a rational under the caller's decimal context, without floats."""
    if isinstance(value, Fraction):
        return Decimal(value.numerator) / Decimal(value.denominator)
    return Decimal(value)


def log2(value: int | Fraction | Decimal) -> Decimal:
    """Compute a diagnostic logarithm; it is never used for exact decisions."""
    return dec(value).ln() / Decimal(2).ln()


def display(value: int | Fraction | Decimal) -> dict[str, str]:
    """Render an approximation plus exact rational data when available."""
    result = {"decimal": format(dec(value), ".24E")}
    if value > 0:
        result["log2"] = format(log2(value), ".16f")
    if isinstance(value, (int, Fraction)):
        rational = Fraction(value)
        result["numerator"] = str(rational.numerator)
        result["denominator"] = str(rational.denominator)
    return result


def oracle_budget(q: int = Q_ADVERSARY) -> int:
    """Equation (38), including worst-case counters and certificate allowance."""
    if q < 0:
        raise ValueError("query counts must be nonnegative")
    return q + 1447 * T + COUNTERS * T + 1024


def soundness(q: int = Q_ADVERSARY, batch: bool = False) -> Fraction:
    """Exact written QROM bound; the global ambiguity event is charged once."""
    budget = oracle_budget(q)
    leaf = 33 * (1 - pow2(-256)) * pow2(-256)
    relation = 340 * budget**3 * pow2(-512) + 70 * budget**2 * pow2(-256)
    return leaf + (1001 if batch else 1) * relation


def last_integer_below(bound: Callable[[int], Fraction], target: Fraction) -> int | None:
    """Find the last nonnegative integer with a strictly smaller exact bound."""
    if bound(0) >= target:
        return None
    low, high = 0, 1
    while bound(high) < target:
        low, high = high, high * 2
    while high - low > 1:
        middle = (low + high) // 2
        if bound(middle) < target:
            low = middle
        else:
            high = middle
    return low


def leaf_vectors(sizes: tuple[int, ...]) -> list[int]:
    """Interleave vector leaves by index, as the frozen heap position rule does."""
    if not sizes or any(size < 1 for size in sizes):
        raise ValueError("nonempty positive vector sizes required")
    return [i for position in range(max(sizes)) for i, size in enumerate(sizes) if position < size]


def expected_opening_seeds(sizes: tuple[int, ...]) -> Fraction:
    """Exactly average the opening size using node nonselection probabilities.

    A boundary edge contributes when its child has no selected leaf and its
    parent does. The common denominator is the number of possible selections.
    This finite calculation does not assume independent random tree nodes.
    """
    leaves = leaf_vectors(sizes)
    count = len(leaves)
    below = [[0] * len(sizes) for _ in range(2 * count - 1)]
    for offset, vector in enumerate(leaves):
        below[count - 1 + offset][vector] = 1
    for node in range(count - 2, -1, -1):
        below[node] = [a + b for a, b in zip(below[2 * node + 1], below[2 * node + 2])]
    absent = [prod(size - value for size, value in zip(sizes, counts)) for counts in below]
    numerator = sum(absent[2 * node + 1] + absent[2 * node + 2] - 2 * absent[node]
                    for node in range(count - 1))
    return Fraction(numerator, prod(sizes))


def known_terms(q: int = Q_ADVERSARY) -> dict[str, Fraction | Decimal]:
    """Equations (59), (74), (79)--(84), (96); no unknown is set to zero."""
    if q < 0:
        raise ValueError("query counts must be nonnegative")
    square = lambda value: dec(value).sqrt()
    p1 = dec(Fraction(3, 2) * T) * square((q + T) * pow2(-256))
    p2 = dec(Fraction(3, 2) * T) * square((q + T) * pow2(-2112))
    p3 = dec(Fraction(3, 2) * T * COUNTERS) * square((q + T) * pow2(-832))
    initial = dec(Fraction(3, 2) * T) * square(256 * 704 * (q + 1408 * T) * pow2(-384))
    mh = (2 + T) * pow2(-256) + 2 * 704 * T**2 * 256 * pow2(-384)
    separation = (T + 2 * 704 * T**2) * pow2(-256)
    salt = Fraction(T * (T - 1), 2) * pow2(-256)
    deletion = 2 * (q + 704 * T) * pow2(-128) + salt
    sigma = dec(T) * (-dec(Fraction(2 * COUNTERS, 7360))).exp()
    exhaustion = dec(T) * (-dec(Fraction(COUNTERS, 7360))).exp()
    k_sim = p2 + p3 + initial + dec(mh + separation + 2 * deletion)
    repetition = Fraction(U * (U - 1), 2) * pow2(-384)
    switching = T * (10 + 396 * 6 + 33 * (36 + 419 * 418 // 2)) * pow2(-128)
    # Alternative diagnostic only: if the leaf game needs N0=256 distinct
    # tweaks under one key, its switching allowance involves 9*N0 blocks.
    # Whether a smaller one-query game suffices requires a separate reduction.
    leaf_multiquery_switching = T * (10 + 396 * 6 + 33 * (2304 * 2303 // 2 + 419 * 418 // 2)) * pow2(-128)
    leaf = 33 * (1 - pow2(-256)) * pow2(-256)
    # Conservative union of listed model/statistical exceptions, with the
    # salt term charged twice to match the two deletions in K_sim.
    statistical = dec(leaf + mh + separation + 2 * salt + 2 * repetition) + sigma
    return {
        "epsilon_P1": p1, "epsilon_P2": p2, "epsilon_P3": p3,
        "epsilon_initial": initial, "delta_MH": mh, "delta_sep": separation,
        "delta_salt": salt, "epsilon_delete": deletion, "twice_deletion": 2 * deletion,
        "K_sim": k_sim, "sigma": sigma, "rho_rep": repetition,
        "global_leaf_ambiguity": leaf, "guess_single": pow2(-512),
        "guess_batch": 1001000 * pow2(-512), "D_sw": switching,
        "N0_query_leaf_switching_diagnostic_not_adopted_bound": leaf_multiquery_switching,
        "programmed_any_exhaustion": exhaustion,
        "written_real_exhaustion_transfer": exhaustion + p1 + p2 + p3,
        "known_C_without_switching": p1 + k_sim + sigma,
        "known_C_with_direct_switching": p1 + k_sim + sigma + dec(switching),
        "listed_statistical_union_without_switching": statistical,
        "listed_statistical_union_with_direct_switching": statistical + dec(switching),
    }


def interactive_terms() -> dict[str, dict[str, dict[str, str]]]:
    """Reproduce component-only bounds (13), (14), (20), (21) for both rows."""
    rows = {}
    for row, tau, denominator_bits in (("candidate", 33, 24), ("comparator", 22, 18)):
        for role, (witness, constraints, expanded) in DIMENSIONS.items():
            polynomial = 1 + (witness + 5)**5 * pow2(-64)
            coefficient = 8 + polynomial / (6 * 2**denominator_bits) + (constraints - 1)**2 * pow2(-64)
            leaf_round = Fraction(tau, 2) * (1 - pow2(-256)) * pow2(-384)
            run = coefficient * pow2(-256) + leaf_round
            a_leaf = 9 * 256 + (expanded + 127) // 128
            exponent = T * (5**2 + 4 * 33 * 12 * 2**2 + 33 * a_leaf**2) * pow2(-128)
            terms = {
                "VOLEHash": polynomial * pow2(-1024),
                "ZKHash": (1 + (constraints - 1)**2 * pow2(-64)) * pow2(-256),
                "leaf_round": leaf_round, "coefficient": coefficient,
                "interactive_run": run, "interactive_lifetime_component": T * run,
            }
            # The recorded PRP-native expression is for the candidate row only.
            if row == "candidate":
                terms["PRP_native_exponent"] = exponent
                terms["PRP_native_factor"] = dec(exponent).exp()
            rows[f"{row}_{role}"] = {name: display(value) for name, value in terms.items()}
    return rows


def resource_inventory() -> dict:
    """Known pooled primitive subtotal; missing costs remain explicitly null."""
    commitment = 4 * 6399 + 9 * 6400 + 419 * 6400 + 1
    entries = {
        "direct_primitive_nominal_cap": Fraction(Q_ADVERSARY),
        "heavy_verification_nominal_allowance": Fraction(2750672 + 2**16, 740) * Q_ADVERSARY,
        "public_validation_nominal_allowance": Fraction(2**12 * Q_ADVERSARY),
        "commitment_plus_reconstruction": Fraction(2 * commitment * T),
        "programmed_counter_keccak_permutations": Fraction(4 * COUNTERS * T),
        "noncounter_honest_keccak_nominal_allowance": Fraction(2**16 * T),
    }
    subtotal = sum(entries.values(), Fraction())
    return {
        "model": "Declared nominal request/direct-primitive caps; not implied by backend queries.",
        "commitment_aes_blocks": commitment,
        "heavy_verification_aes_blocks": 2750672,
        "minimum_charged_backend_calls_per_heavy_verification": 740,
        "pooled_AES_blocks_Keccak_permutations": {name: display(value) for name, value in entries.items()},
        "known_pooled_subtotal": display(subtotal),
        "strict_2pow77_headroom_for_unaccounted_primitive_work": display(Q_NOMINAL - subtotal),
        "final_comparison_allowance": None,
        "total_primitive_bound": None,
        "public_request_cap_enforcement": None,
        "direct_primitive_cap_enforcement": None,
        "simulator_max_normal_counter_trials": COUNTERS * T,
        "simulator_max_additional_exhaustion_sampler_trials": COUNTERS * T,
        "simulator_max_total_uniform_256bit_draws": 2 * COUNTERS * T,
        "simulator_max_bits_for_those_draws": 256 * 2 * COUNTERS * T,
        "simulator_admissibility_checks": 2 * COUNTERS * T,
        "relation_and_transcript_evaluations": {"invocations": T, "gate_cost": None},
        "sampler_gate_cost": None,
        "aes_keccak_elementary_gate_conversion": None,
        "credential_and_context_generation_gate_cost": None,
        "table_lookup_memory_qram_and_coherent_access_cost": None,
        "primitive_dependent_preprocessing_and_advice": None,
        "total_runtime_gate_memory_resource_vector": None,
    }


def frame_collision_diagnostic(queries: int = Q_NOMINAL, max_frame_bytes: int = 128536) -> dict:
    """Thm 5.5 random-permutation diagnostic, including XOR/swap conversion.

    Two output messages, SHA3-512 rate 576/capacity 1024, digest 512. For a
    byte-aligned message its suffix plus padding uses floor(bytes/72)+1
    rate blocks. The theorem counts swap queries, twice ordinary XOR access.
    """
    if queries < 0 or max_frame_bytes < 0:
        raise ValueError("nonnegative query and length limits required")
    output_blocks = 2 * (max_frame_bytes // 72 + 1)
    t = 2 * queries + 2 * output_blocks
    valid = t <= 1 << 798
    value = 32 * t**3 * pow2(-512) + 128 * t**3 * pow2(-1024) + 32768 * t**2 * pow2(-1600)
    return {"model": "random permutation only; not a concrete SHA3-512 bound",
            "ordinary_xor_queries": queries, "output_message_blocks_total": output_blocks,
            "swap_queries_plus_twice_output_blocks": t, "theorem_size_condition": valid,
            "collision_upper_bound": display(value) if valid else None,
            "concrete_frame_bound": None}


def nominal_games(terms: dict[str, Fraction | Decimal]) -> dict[str, Decimal | Fraction]:
    """Hypothetical substitution from §8.5, kept outside the qualified ledger."""
    generator = 463 * T * Q_NOMINAL**2 * pow2(-256)
    pseudorandomness = 4 * dec(Q_NOMINAL) * dec(Fraction(U, 2**384 - U)).sqrt()
    uniqueness = pow2(-233)
    frame = 64 * Q_NOMINAL**3 * pow2(-512)
    z = terms["known_C_with_direct_switching"] + dec(generator)
    shared = z + pseudorandomness + dec(uniqueness + frame + terms["rho_rep"])
    p2 = dec(soundness()) + shared + dec(terms["guess_single"])
    p8 = p2
    return {"hypothetical_T_e_gen": generator, "hypothetical_alpha_P": pseudorandomness,
            "hypothetical_each_U": uniqueness, "hypothetical_each_frame": frame,
            "property_1_conditional": soundness(), "property_2": p2,
            "property_3": dec(soundness(batch=True)) + shared + dec(terms["guess_batch"]),
            "property_8": p8, "joint_zero_knowledge": z,
            "anonymity_and_unlinkability": 2 * z + 2 * pseudorandomness + 2 * dec(terms["rho_rep"]),
            "combined_nonframeability": p2 + p8}


def unknown_bounds() -> dict[str, None]:
    """Required concrete entries; absent evidence can never become numeric zero."""
    return dict.fromkeys((
        "generator_joint_root", "generator_hidden_tree", "generator_correlated_nine_block_leaf",
        "generator_expanded_rows", "credential_P", "uniqueness_Com_seal",
        "uniqueness_Com_target", "uniqueness_tag_target", "frame_REG", "frame_VOTE",
        "frame_VOTE_batch", "concrete_backend_oracle_justification",
        "complete_reduction_resource_vector", "reviewed_adaptive_soundness_embedding",
        "reviewed_extended_CRT_and_joint_simulation", "independent_attack_cost_assessment",
        "explicit_owner_contract_acceptance",
    ))


def build_report() -> dict:
    """Create the deterministic 160-digit ledger and exact consistency checks."""
    with localcontext() as context:
        context.prec = PRECISION
        terms = known_terms()
        expectation = expected_opening_seeds((256,) * 17 + (128,) * 16)
        exact_expected = Fraction(EXPECTED_SEED_NUMERATOR, 2**248)
        p1_at_zero = 3 * pow2(-63)
        nominal = nominal_games(terms)
        sound_cutoffs = {}
        for batch in (False, True):
            for name, target in (("half", Fraction(1, 2)), ("2pow_minus64", pow2(-64))):
                cutoff = last_integer_below(lambda q: soundness(q, batch), target)
                sound_cutoffs[f"{'batch' if batch else 'single'}_{name}"] = {
                    "largest_q_strictly_below": cutoff,
                    "bound_at_q": display(soundness(cutoff, batch)),
                    "bound_at_q_plus_one": display(soundness(cutoff + 1, batch)),
                    "target": display(target),
                }
        residuals = {}
        for formulation in ("without_switching", "with_direct_switching"):
            c = dec(terms[f"known_C_{formulation}"])
            residuals[formulation] = {
                "half_property_2_and_8_unknown_sum": display(dec(Fraction(1, 2) - soundness() - terms["rho_rep"] - terms["guess_single"]) - c),
                "half_property_3_unknown_sum": display(dec(Fraction(1, 2) - soundness(batch=True) - terms["rho_rep"] - terms["guess_batch"]) - c),
                "half_JZK_T_e_gen": display(Decimal("0.5") - c),
                "half_privacy_T_e_gen_plus_alpha_P": display(Decimal("0.25") - c - dec(terms["rho_rep"])),
                "half_nonframeability_unknown_sum": display(dec(Fraction(1, 2) - 2 * soundness() - 2 * terms["rho_rep"] - 2 * terms["guess_single"]) - 2 * c),
                "2pow_minus64_property_2_and_8_unknown_sum": display(dec(pow2(-64) - soundness() - terms["rho_rep"] - terms["guess_single"]) - c),
                "2pow_minus64_property_3_unknown_sum": display(dec(pow2(-64) - soundness(batch=True) - terms["rho_rep"] - terms["guess_batch"]) - c),
                "2pow_minus64_JZK_T_e_gen": display(dec(pow2(-64)) - c),
                "2pow_minus64_privacy_T_e_gen_plus_alpha_P": display(dec(pow2(-65)) - c - dec(terms["rho_rep"])),
                "2pow_minus64_nonframeability_unknown_sum": display(dec(pow2(-64) - 2 * soundness() - 2 * terms["rho_rep"] - 2 * terms["guess_single"]) - 2 * c),
            }
        ideal = {
            "fixed_context_whole_secret_map_noninjectivity": Fraction(2**384 * (2**384 - 1), 2) * pow2(-1024),
            "fixed_honest_target_other_opening": (2**384 - 1) * pow2(-1024),
            "alpha_P_table_at_original_queries": 4 * dec(Q_ADVERSARY) * dec(Fraction(U, 2**384 - U)).sqrt(),
        }
        ideal["J_fixed_context_whole_map_union"] = J * ideal["fixed_context_whole_secret_map_noninjectivity"]
        ideal["U_fixed_honest_targets_union"] = U * ideal["fixed_honest_target_other_opening"]
        ideal["T_fixed_targets_union"] = T * ideal["fixed_honest_target_other_opening"]
        checks = {
            "budget_matches_record": oracle_budget() == 36918944040625374208,
            "exact_heap_expectation_matches_record": expectation == exact_expected,
            "heap_expectation_below_222": expectation < 222,
            "Markov_plus_grinding_bound": (1 - Fraction(222, 230)) / 256 == Fraction(1, 7360),
            "P1_at_zero_equals_six_times_target": p1_at_zero == 6 * pow2(-64),
            "listed_statistical_union_excluding_switching_below_budget": terms["listed_statistical_union_without_switching"] < dec(pow2(-128)),
            "direct_switching_exceeds_statistical_budget": terms["D_sw"] > pow2(-128),
            "known_only_Z_at_ceiling_exceeds_2pow_minus64": terms["known_C_without_switching"] > dec(pow2(-64)),
        }
        return {
            "schema": "parliament-ballot-b6-security-ledger-1",
            "precision_decimal_digits": PRECISION,
            "scope": "Arithmetic/transcription and source-hypothesis evidence; no cryptographic qualification.",
            "arithmetic_checks_pass": all(checks.values()), "checks": checks,
            "qualified": False, "production_approved": False,
            "unknown_required_bounds_or_evidence": unknown_bounds(),
            "certified_complete_query_thresholds": {"half": None, "2pow_minus64": None},
            "parameters": {"q": Q_ADVERSARY, "T": T, "U": U, "J": J, "Q_star_nominal": Q_NOMINAL, "M_ctr": COUNTERS, "Q_written_soundness": oracle_budget()},
            "known_terms": {name: display(value) for name, value in terms.items()},
            "soundness_conditional_exact_thresholds": sound_cutoffs,
            "interactive_components_not_added_to_adaptive_soundness": interactive_terms(),
            "heap_expectation": display(expectation),
            "P1_at_zero_external_queries": display(p1_at_zero),
            "written_Z_2pow_minus64_query_cutoff_at_fixed_T": None,
            "written_Z_cutoff_reason": "Even q=0 gives P1=6*2^-64; no nonnegative q suffices for this written bound.",
            "unknown_sum_residuals_individual_not_simultaneous_allocations": residuals,
            "ideal_function_diagnostics_not_concrete_P_or_U": {name: display(value) for name, value in ideal.items()},
            "random_permutation_frame_diagnostic": frame_collision_diagnostic(),
            "nominal_substitution_not_qualification": {name: display(value) for name, value in nominal.items()},
            "resource_inventory": resource_inventory(),
        }


def main(argv: list[str] | None = None) -> int:
    """CLI: arithmetic success is distinct from qualification, which is absent."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit the deterministic complete ledger")
    parser.add_argument("--require-qualified", action="store_true", help="exit 2 unless every qualification obligation is discharged (currently never)")
    args = parser.parse_args(argv)
    report = build_report()
    if args.json:
        print(json.dumps(report, sort_keys=True, indent=2))
    else:
        print(f"Arithmetic checks: {'PASS' if report['arithmetic_checks_pass'] else 'FAIL'}")
        print("Security qualification: UNRESOLVED; production approval: false")
        print("Written Z target 2^-64: no nonnegative query cutoff at T=2^44 (P1(0)=6*2^-64)")
        print(f"Missing obligations: {len(report['unknown_required_bounds_or_evidence'])}")
    if not report["arithmetic_checks_pass"]:
        return 1
    if args.require_qualified and not report["qualified"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
