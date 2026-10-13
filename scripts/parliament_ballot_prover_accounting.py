#!/usr/bin/env python3
"""Count the implemented ballot prover's non-counter Keccak component.

Python 3.11+, repository sources, no third-party packages or builds. This is a
source-derived primitive-call calculation, not a gate, simulator, runtime or
cryptographic certificate. --require-qualified always refuses qualification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import types

ROOT = Path(__file__).resolve().parents[1]
MODEL = Path("scripts/check_parliament_ballot_resource_accounting.py")
REVIEWED_SOURCE_SHA256 = "49d7fa0af0dc1211d7d10a7835b2f2b335b76c360117b67c36dd31fa474c4ca1"
ALLOWANCE = 65_536
MAX_ATTEMPTS = 1 << 20
ROWS = {"candidate": (33, 8, 704), "comparator": (22, 6, 696)}
WITNESS_BITS = {"registration": 35_840, "vote": 53_504}


def source_inventory(root: Path) -> dict[str, str]:
    """Identify reviewed source formulas, including every prover/credential module."""
    paths = {MODEL.as_posix()}
    for directory in ("crates/iroha_parliament_ballot_proof/src", "crates/iroha_zkp_vole/src",
                      "vendor/aes/src"):
        paths.update(path.relative_to(root).as_posix() for path in (root / directory).rglob("*.rs"))
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in sorted(paths)}


def inventory_digest(inventory: dict[str, str]) -> str:
    """Hash the canonical ordered source inventory, independent of mtime."""
    return hashlib.sha256(json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def load_model(root: Path):
    """Load exact pinned helper bytes, avoiding an unrelated cached Python module."""
    path = root / MODEL
    source = path.read_bytes()
    module = types.ModuleType("prover_reviewed_resource_model")
    module.__file__ = str(path)
    exec(compile(source, str(path), "exec"), module.__dict__)
    return module, hashlib.sha256(source).hexdigest()


def sponge(input_bytes: int, output_bytes: int, rate: int = 136) -> int:
    """Count full absorb blocks, final padding, and additional squeeze blocks."""
    if input_bytes < 0 or output_bytes < 0 or rate not in (72, 136):
        raise ValueError("invalid SHA3-512/SHAKE256 dimensions")
    return input_bytes // rate + 1 + max(0, (output_bytes - 1) // rate)


def schedule(parts: list[tuple[int, int, int, int]]) -> dict:
    """Sum explicit (calls, input bytes, output bytes, rate bytes) entries."""
    if any(count < 0 for count, _, _, _ in parts):
        raise ValueError("negative invocation count")
    return {"calls": sum(count for count, _, _, _ in parts),
            "absorbed_bytes": sum(count * size for count, size, _, _ in parts),
            "squeezed_bytes": sum(count * size for count, _, size, _ in parts),
            "keccak_f1600": sum(count * sponge(size, output, rate)
                                for count, size, output, rate in parts),
            "parts": [{"calls": count, "input_bytes": size, "output_bytes": output, "rate_bytes": rate}
                      for count, size, output, rate in parts]}


def total(hashes: dict) -> int:
    """Sum permutation counts in a named phase schedule, without pricing gates."""
    return sum(value["keccak_f1600"] for value in hashes.values())


def profile_schedule(crt_words: int) -> dict:
    """One fresh Profile: CRT digest, descriptor, and both role namespaces."""
    return {name: schedule([(1, size, 64, rate)]) for name, size, rate in (
        ("profile_crt_shake256", 8 * crt_words, 136),
        ("profile_descriptor_sha3_512", 286, 72),
        ("profile_namespace_reg_sha3_512", 89, 72),
        ("profile_namespace_vote_sha3_512", 90, 72))}


def frontend_schedule(role: str, seats: int, crt_words: int) -> dict:
    """The ordinary typed prove entry; bounded public frames precede its backend."""
    if role not in WITNESS_BITS or not 3 <= seats <= 1000:
        raise ValueError("unsupported prover shape")
    hashes = profile_schedule(crt_words)
    calls = (("registration_authorization_sha3_512", 5975, 72),
             ("message_shake256", 6024, 136)) if role == "registration" else (
        ("list_sha3_512", 128 * seats + 114, 72),
        ("vote_authorization_sha3_512", 128 * seats + 536, 72),
        ("message_shake256", 128 * seats + 584, 136))
    hashes.update({name: schedule([(1, size, 64, rate)]) for name, size, rate in calls})
    return hashes


def setup_schedule(role: str, seats: int, crt_words: int) -> dict:
    """Optional Profile::new + Statement::for_secret, with bounded inputs supplied.

    Vote inputs already include the sealed list and body/scope/policy digests;
    this does not generate S credentials or hash arbitrary policy preimages.
    """
    if role not in WITNESS_BITS or not 3 <= seats <= 1000:
        raise ValueError("unsupported statement setup shape")
    hashes = profile_schedule(crt_words)
    calls = (("body_digest_sha3_512", 4136),
             ("registration_authorization_sha3_512", 5975)) if role == "registration" else (
        ("list_sha3_512", 128 * seats + 114),
        ("vote_authorization_sha3_512", 128 * seats + 536))
    hashes.update({name: schedule([(1, size, 64, 72)]) for name, size in calls})
    # Each credential::shake calls the explicit 24-round lane evaluator once.
    hashes["credential_lane_evaluations"] = schedule([(1, 132, 128, 136), (1, 132, 64, 136)])
    return hashes


def backend_schedule(row: str, role: str) -> dict:
    """All pre-counter prover hashes; H5 evaluates both labels of every gate."""
    if row not in ROWS or role not in WITNESS_BITS:
        raise ValueError("unsupported backend shape")
    tau, grind, gates = ROWS[row]
    ell_bytes = WITNESS_BITS[role] // 8
    short, long_count = divmod(256 - grind, tau)
    depths = [short + 1] * long_count + [short] * (tau - long_count)
    parts = {
        "H0": [(1, 77 + 16 + 1, 128, 136)],
        "H1_vectors": [(1, 77 + (1 << depth) * 112 + 1, 64, 136) for depth in depths],
        "H1_outer": [(1, 77 + 64 * tau + 1, 64, 136)],
        "H4": [(1, 77 + 16 + 64 + 1, 16, 136)],
        "challenge_1": [(1, 77 + 64 + 64 + (tau - 1) * ell_bytes
                         + 10 * ((gates + 7) // 8) + 16 + 32 + 1, 264, 136)],
        "challenge_2": [(1, 77 + 264 + 128 + 128 + ell_bytes + 1, 104, 136)],
        "H5": [(2 * gates, 77 + 16 + 32 + 4 + 32 + 1, 2, 136)],
    }
    return {name: schedule(entries) for name, entries in parts.items()}


def counter_work(attempts: int) -> dict:
    """Count the cloned Challenge3 state for a normal-return retry execution.

    A=0 means the backend rejected before creating Challenge3. For A>=1 its
    405-byte prefix is absorbed once (two permutations,133 bytes buffered).
    Each at adds counter4 + domain1 and padding, performing two permutations.
    This includes failed grinding/opening attempts; neither failure adds a hash.
    """
    if type(attempts) is not int or not 0 <= attempts <= MAX_ATTEMPTS:
        raise ValueError("attempt count outside extended construction")
    exact = 2 + 2 * attempts if attempts else 0
    return {"attempts": attempts, "prefix_permutations": 2 if attempts else 0,
            "per_attempt_permutations": 2, "keccak_f1600": exact,
            "ledger_upper_bound": 4 * attempts, "ledger_inequality_holds": exact <= 4 * attempts}


def preimage_counterexample() -> dict:
    """Show why optional arbitrary policy/proposal hashing is outside this bound."""
    length = (1 << 32) - 1
    result = {}
    for name, tag, leading in (("policy", b"PARL/POLICY/v1", [16]),
                               ("proposal", b"PARL/PROPOSAL/v1", [])):
        size = 2 + len(tag) + 2 + 4 * (len(leading) + 1) + sum(leading) + length
        result[name] = {"preimage_bytes": length, "frame_bytes": size,
                        "keccak_f1600": sponge(size, 64, 72),
                        "fits_65536": sponge(size, 64, 72) <= ALLOWANCE}
    return result


def case(model, row: str, role: str, seats: int, tables: dict) -> dict:
    """Compose one reviewed source shape and crosscheck the older verifier model."""
    front = frontend_schedule(role, seats, tables["canonical_words"])
    backend = backend_schedule(row, role)
    setup = setup_schedule(role, seats, tables["canonical_words"])
    witness_evaluations = 2 if role == "registration" else 3
    core = total(front) + total(backend) + witness_evaluations
    with_setup = core + total(setup)
    old_front = model.statement_schedule(role, seats, tables, False)["hashes"]
    old_backend = model.backend_schedule(row, role, seats, tables)["sponges"]
    fields = ("calls", "absorbed_bytes", "squeezed_bytes", "keccak_f1600")
    front_agrees = (set(front) == {name for name, value in old_front.items() if value["calls"]}
                    and all(front[name][key] == value[key]
                            for name, value in old_front.items() if value["calls"] for key in fields))
    backend_agrees = (set(backend) == set(old_backend) - {"challenge_3"}
                      and all(backend[name][key] == value[key] * (2 if name == "H5" else 1)
                              for name, value in old_backend.items() if name != "challenge_3"
                              for key in fields))
    return {"row": row, "role": role, "seats": seats if role == "vote" else None,
            "ordinary_public_preparation": front, "backend_non_counter": backend,
            "witness_lane_evaluations": witness_evaluations,
            "ordinary_prove_non_counter_keccak": core,
            "optional_for_secret_setup": setup,
            "for_secret_then_prove_non_counter_keccak": with_setup,
            "allowance": ALLOWANCE, "ordinary_margin": ALLOWANCE - core,
            "with_setup_margin": ALLOWANCE - with_setup,
            "within_allowance": core <= ALLOWANCE and with_setup <= ALLOWANCE,
            "verifier_schedule_crosscheck": front_agrees and backend_agrees,
            "successful_opening_extra_aes_blocks": 9 * ROWS[row][0],
            "failed_opening_extra_aes_blocks": 0}


def report(root: Path = ROOT) -> dict:
    """Refuse source drift and retain all unproved reduction/resource gates."""
    sources = source_inventory(root)
    aggregate = inventory_digest(sources)
    result = {"schema": "parliament-real-prover-accounting-v1", "source_sha256": sources,
              "source_manifest_sha256": aggregate, "reviewed_source_manifest_sha256": REVIEWED_SOURCE_SHA256,
              "source_matched": aggregate == REVIEWED_SOURCE_SHA256,
              "source_real_prover_component_checked": False,
              "complete_honest_oracle_or_simulator_bound": False,
              "complete_primitive_resource_bound": False, "complete_gate_or_memory_bound": False,
              "profile_qualified": False}
    if not result["source_matched"]:
        return {**result, "failure": "reviewed prover sources changed; review before repinning"}
    model, helper_hash = load_model(root)
    if helper_hash != sources[MODEL.as_posix()]:
        return {**result, "failure": "formula helper changed during loading"}
    tables = {row: model.table_inventory(root, row) for row in ROWS}
    selected, checked, maxima = [], True, {}
    for row in ROWS:
        registration = case(model, row, "registration", 3, tables[row])
        votes = [case(model, row, "vote", seats, tables[row]) for seats in range(3, 1001)]
        checked &= all(item["within_allowance"] and item["verifier_schedule_crosscheck"]
                       for item in [registration, *votes])
        monotone = all(a["for_secret_then_prove_non_counter_keccak"] <= b["for_secret_then_prove_non_counter_keccak"]
                       for a, b in zip(votes, votes[1:]))
        checked &= monotone
        maxima[row] = {"vote_sizes_checked": len(votes), "vote_cost_monotone": monotone,
                       "ordinary_prove": votes[-1]["ordinary_prove_non_counter_keccak"],
                       "for_secret_then_prove": votes[-1]["for_secret_then_prove_non_counter_keccak"]}
        selected += [registration, *[votes[seats - 3] for seats in (3, 500, 1000)]]
    # Loading/running imported count code must not make a mid-run pin change invisible.
    after = source_inventory(root)
    checked &= after == sources
    return {**result, "source_real_prover_component_checked": checked,
            "failure": None if checked else "count, allowance, helper comparison or source stability failed",
            "source_stable": after == sources,
            "helper_loaded_sha256": helper_hash,
            "artifact_sha256": {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in (
                "scripts/parliament_ballot_prover_accounting.py",
                "scripts/tests/parliament_ballot_prover_accounting_test.py")},
            "selected_cases": selected, "maxima": maxima,
            "counter_cap": counter_work(MAX_ATTEMPTS), "preimage_scope_counterexample": preimage_counterexample(),
            "exclusions": [
                "Full simulator, hybrid emulation, final comparison and honest-oracle game driver",
                "Caller RNG/tape/secret generation; existing sealed-list credentials and arbitrary context preimages",
                "Relation is_satisfied and QuickSilver field/gate work (not sponge invocations)",
                "AES provider gates/key schedules, copying/zeroization/encoding, runtime and allocator work",
                "Process abort, asynchronous cancellation and out-of-memory interruption",
                "Quantum oracle maintenance, coherent access, memory, advice and preprocessing",
                "Production framing/ingress and independent human assessment"]}


def main() -> int:
    """Print component evidence; qualification remains deliberately unavailable."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--require-qualified", action="store_true")
    args = parser.parse_args()
    result = report()
    print(json.dumps(result, indent=2, sort_keys=True) if args.json else
          f"Real prover component: {result['source_real_prover_component_checked']}; qualification: False")
    if not result["source_real_prover_component_checked"]:
        return 1
    return 2 if args.require_qualified else 0


if __name__ == "__main__":
    raise SystemExit(main())
