# Lattice Estimator run for the iroha_fhe RNS-BGV starting candidates.
#
# STATUS: RUN on 2026-10-06 with SageMath 10.9 and the estimator at the pinned
# commit, on an Apple M1 Ultra (Mac13,2, Darwin 27.0.0) that was running other
# builds. The complete raw output of every invocation, with the versions, the
# host, the dates and the exact commands, is tracked in
# specs/fhe_bgv_lattice_estimator_output.txt. specs/fhe_bgv_cost_summary.json
# restates it under `security_estimate.lattice_estimator`, and
# scripts/fhe_bgv_cost_model.py holds the summary to the record and the record
# to the code below this header (a hash of it is in every RUN line), so a
# change of that code needs a new run.
#
# What the record holds. It is the concatenation of eleven invocations, split
# by attack so that the cheap attacks did not wait behind the slow ones:
#
# * the self-check: the calls of this script equal `LWE.estimate` on Kyber512
#   for every attack and cost model;
# * primal uSVP, primal BDD, dual and dual hybrid for every profile, instance
#   and cost model: all 180 returned a cost;
# * the primal hybrid attack on the three candidates at modulus Q * P: all 18
#   returned a cost, after 10 to 17 minutes each at N = 2^14 and 38 to 48
#   minutes each at N = 2^16;
# * the meet-in-the-middle hybrid on the same instances: 3 of 18 returned a
#   cost (the affine candidate, after 55 minutes each), 10 were stopped when
#   the job ended and 5 never started;
# * Arora-GB on the candidates at Q * P: an infinite cost once, the 16 GiB
#   memory limit five times; coded BKW with unlimited samples: the 60-minute
#   limit for all three candidates;
# * shapes outside the pinned list (`--shape`): proposals that change no
#   profile.
#
# Hybrid attacks, Arora-GB and BKW were not run on the modulus Q or on the
# two measured configurations. Every attack without a cost is in the record
# or reported by the summary with its reason, and is not evidence that the
# attack is expensive. The time limits are wall-clock limits on a host whose
# load average was between 43 and 130 on 20 logical CPUs when the invocations
# started.
#
# Before 2026-10-06 this file had never been executed. Running it found two
# defects of the first version, both corrected without touching a parameter:
# the logarithm it printed for a modulus overflowed to `inf` at N = 2^16, and
# `LWE.estimate` prints a hybrid attack only when it beats the attack before
# it and returns nothing for the others when one attack does not finish.
#
# Purpose
# -------
# Costs the published ring-LWE samples of every RNS-BGV profile of
# specs/fhe_bgv_cost_summary.json with the Lattice Estimator of Albrecht et al.
# and prints a raw record that scripts/fhe_bgv_cost_model.py reads. A result is
# an estimate under the assumptions below. It qualifies no profile.
#
# Prerequisites: SageMath >= 10 and a checkout of the estimator at the pinned
# commit. No environment variable other than PYTHONPATH is read, nothing is
# downloaded and nothing is written except standard output.
#
#   git clone https://github.com/malb/lattice-estimator
#   git -C lattice-estimator checkout 53da5982597709ba0fdf94ea37a84d822310fd84
#   PYTHONPATH=lattice-estimator sage scripts/fhe_bgv_lattice_estimator.sage \
#       > specs/fhe_bgv_lattice_estimator_output.txt
#
# The pinned commit is the head of the estimator's main branch on 2026-10-05.
# `--help` lists the selectors (`--profile`, `--instance`, `--model`,
# `--attack`), the limits (`--timeout`, `--memory-limit-gib`), `--parallel`,
# `--shape` for a parameter set outside the pinned list and `--self-check`.
# Several invocations may be concatenated into one record: every line that
# carries data names its profile, instance, cost model and attack.
#
# `sage file.sage` writes the preparsed source to `file.sage.py` and runs that
# copy. This script removes the copy as soon as it runs, so a run leaves
# nothing in the source tree; start a second run only after the copy of the
# first is gone, which takes a few seconds.
#
# What is estimated
# -----------------
# Every published object of the scheme is a ring-LWE sample in
# Z_q[X]/(X^N + 1):
#
# * the public key, modulo Q = q_0 * ... * q_L, under the secret key s;
# * a fresh ciphertext, two polynomials modulo Q, under its own mask u, which
#   has the distribution of s;
# * the relinearization and Galois keys, modulo Q * P, under s: one polynomial
#   per key-switching digit and key.
#
# Samples have the form b = -a*s + t*e with gcd(t, q) = 1, so multiplying by
# t^-1 yields ordinary samples with error e: the error distribution of the
# estimate is that of e, not of t*e.
#
# * secret: uniform ternary (each coefficient -1, 0, 1 with probability 1/3;
#   crates/iroha_fhe/src/bgv/coins.rs, `ternary`);
# * error: centered binomial with eta = 21 (support [-21, 21], variance 10.5;
#   `centered_binomial` and `ERROR_ETA` of the same file);
# * dimension n = N; the estimator treats ring-LWE as LWE of that dimension,
#   which ignores the ring structure;
# * moduli: the pinned primes of crates/iroha_fhe/src/bgv/profile.rs, which
#   this script derives by the first-prime rule and compares with that file
#   before it estimates anything;
# * instances: `Q:n` (the public key: modulus Q, m = n samples), `QP:n` (one
#   switching-key polynomial: modulus Q * P, m = n) and `QP:oo` (modulus
#   Q * P, unlimited samples). A sample modulo Q * P reduces to one modulo Q,
#   so `QP:oo` is the conservative instance for every exposure of s: a key set
#   publishes n * digits * (1 + Galois keys) samples modulo Q * P.
#
# Attacks: those of `LWE.estimate` at the pinned commit (estimator/lwe.py,
# `Estimate.__call__`) with its settings: primal uSVP (`usvp`), primal BDD
# (`bdd`), the primal hybrid attacks (`bdd_hybrid`, `bdd_mitm_hybrid`), dual
# (`dual`), dual hybrid (`dual_hybrid`), and the two attacks that take no
# reduction cost model, Arora-GB with guessing (`arora-gb`) and coded BKW
# (`bkw`). Each attack runs in a process of its own under a time and a memory
# limit, so that one attack that does not finish costs nothing else, and its
# complete cost dictionary is printed: `LWE.estimate` itself prints a hybrid
# attack only when it beats the attack before it. `--self-check` compares the
# calls of this script with `LWE.estimate` on a small parameter set.
#
# Cost models: RC.BDGL16 (classical), RC.ADPS16 (classical) and ADPS16 in
# quantum mode. The target recorded by the plan's design memo is at least 128
# bits classically under BDGL16, with quantum costs reported separately.
#
# Not covered: the circular-security (key-dependent message) assumption of
# publishing encryptions of s^2 and s(X^k) under s; any use of the ring
# structure; keys or ciphertexts that were not sampled honestly; side
# channels; decryption failures (the scheme admits no operation whose
# worst-case noise bound exceeds the capacity).
#
# Output
# ------
# Text lines for a reader, and five kinds of lines that carry one JSON object
# each: `RUN` (versions, host, date, command, limits), `INSTANCE` (one LWE
# instance with its exact modulus), `RESULT` (one attack on one instance under
# one cost model; `log2_rop` is the base-two logarithm of the estimated cost
# or "oo"), `SELFCHECK` and `END`. The `status` of a result is `ok`, or says
# why there is no cost: `timeout`, `memory_limit`, `error` (what the estimator
# raised), and, when SIGTERM or SIGINT stopped the run, `stopped` for an
# attack that was running and `not_started` for one that had not begun.

import argparse
import builtins
import datetime
import hashlib
import json
import multiprocessing
import os
import platform
import re
import signal
import subprocess
import sys
import time
from functools import partial
from pathlib import Path

SOURCE = Path(__file__).resolve()
if SOURCE.name.endswith(".sage.py"):
    # The preparsed copy `sage file.sage` runs; the interpreter has read it by now.
    try:
        SOURCE.unlink()
    except OSError:
        pass
ROOT = SOURCE.parent.parent

import estimator
from estimator import LWE, ND, RC
from estimator.conf import red_shape_model as red_shape_model_default
from estimator.gb import arora_gb
from estimator.lwe_guess import guess_composition
from estimator.reduction import ADPS16
from estimator.schemes import Kyber512
from sage.all import RR, ZZ, Primes, oo, prod, version

ESTIMATOR_COMMIT = "53da5982597709ba0fdf94ea37a84d822310fd84"
ERROR_ETA = 21
PROFILE_SOURCE = "crates/iroha_fhe/src/bgv/profile.rs"
COINS_SOURCE = "crates/iroha_fhe/src/bgv/coins.rs"

# name: (log2 N, plaintext modulus, (main bits, main count), (special bits, special count))
PROFILES = {
    "bgv.f257.n14.q6x50.p2x60": (14, 257, (50, 6), (60, 2)),
    "bgv.f257.n16.q22x50.p2x60": (16, 257, (50, 22), (60, 2)),
    "bgv.f257.n16.q32x50.p2x60": (16, 257, (50, 32), (60, 2)),
    # The measured fully splitting comparator; not a RAM-LFE candidate.
    "bgv.derive.n16.t786433.q25x60.p3x60.d2": (16, 786433, (60, 25), (60, 3)),
    # The measured affine instruction-timing configuration; not a candidate.
    "bgv.derive.n14.t257.q13x50.p2x60.d2": (14, 257, (50, 13), (60, 2)),
}
# Candidate: (main table, main primes used, special table) of PROFILE_SOURCE.
PINNED_TABLES = {
    "bgv.f257.n14.q6x50.p2x60": ("F257_N14_MAIN_PRIMES", 6, "F257_N14_SPECIAL_PRIMES"),
    "bgv.f257.n16.q22x50.p2x60": ("F257_N16_MAIN_PRIMES", 22, "F257_N16_SPECIAL_PRIMES"),
    "bgv.f257.n16.q32x50.p2x60": ("F257_N16_MAIN_PRIMES", 32, "F257_N16_SPECIAL_PRIMES"),
}
# (modulus, samples): Q or Q * P; m = n or unlimited.
INSTANCES = ("Q:n", "QP:n", "QP:oo")
# Reduction cost models; "none" selects the attacks that take none.
MODELS = {
    "BDGL16": RC.BDGL16,
    "ADPS16": RC.ADPS16,
    "ADPS16-quantum": ADPS16(mode="quantum"),
}
MODEL_FREE = "none"
LATTICE_ATTACKS = ("usvp", "bdd", "bdd_hybrid", "bdd_mitm_hybrid", "dual", "dual_hybrid")
MODEL_FREE_ATTACKS = ("arora-gb", "bkw")


def lattice_attacks(model):
    """The lattice attacks of `LWE.estimate` at the pinned commit, with its settings."""
    shape = red_shape_model_default
    return {
        "usvp": partial(LWE.primal_usvp, red_cost_model=model, red_shape_model=shape),
        "bdd": partial(LWE.primal_bdd, red_cost_model=model, red_shape_model=shape),
        "bdd_hybrid": partial(
            LWE.primal_hybrid, mitm=False, babai=False, red_cost_model=model, red_shape_model=shape
        ),
        "bdd_mitm_hybrid": partial(
            LWE.primal_hybrid, mitm=True, babai=True, red_cost_model=model, red_shape_model=shape
        ),
        "dual": partial(LWE.dual, red_cost_model=model),
        "dual_hybrid": partial(LWE.dual_hybrid, red_cost_model=model),
    }


def model_free_attacks():
    """The attacks of `LWE.estimate` that take no reduction cost model."""
    return {"arora-gb": guess_composition(arora_gb), "bkw": LWE.coded_bkw}


def rounded(value, digits):
    """`value` as a Python float with `digits` decimals; the preparser replaces `round` by Sage's."""
    return builtins.round(float(value), int(digits))


def log2_of(value):
    """Base-two logarithm as a Python float; exact integers of any size go through a real field."""
    return float(RR(value).log(2))


def first_primes(bits, step, count, skip=()):
    """The first `count` primes of exactly `bits` bits congruent to one modulo `step`."""
    out = []
    candidate = ((1 << (bits - 1)) // step + 1) * step + 1
    while len(out) < count:
        if candidate >= 1 << bits:
            raise ValueError("no prime of the requested size")
        if candidate in Primes() and candidate not in skip:
            out.append(candidate)
        candidate += step
    return out


def primes_of(shape):
    log_degree, plaintext, main, special = shape
    step = 2 * (1 << log_degree) * plaintext
    main_primes = first_primes(main[0], step, main[1])
    special_primes = first_primes(special[0], step, special[1], tuple(main_primes))
    return main_primes, special_primes


def moduli(shape):
    main_primes, special_primes = primes_of(shape)
    return ZZ(prod(main_primes)), ZZ(prod(special_primes))


def source_problems(root):
    """Disagreements between the parameters of this script and the Rust sources that own them."""
    problems = []
    text = (root / PROFILE_SOURCE).read_text()
    tables = {}
    for name, body in re.findall(r"const (F257_N1[46]_(?:MAIN|SPECIAL)_PRIMES): \[u64; \d+\] = \[(.*?)\];", text, re.S):
        tables[name] = [int(item.replace("_", "")) for item in re.findall(r"[0-9_]+", body) if item.strip("_")]
    for name, (main_table, main_count, special_table) in PINNED_TABLES.items():
        main_primes, special_primes = primes_of(PROFILES[name])
        if [int(prime) for prime in main_primes] != tables.get(main_table, [])[:main_count]:
            problems.append(f"{PROFILE_SOURCE}: the main primes of {name} differ from {main_table}")
        if [int(prime) for prime in special_primes] != tables.get(special_table):
            problems.append(f"{PROFILE_SOURCE}: the special primes of {name} differ from {special_table}")
        if f'"{name}"' not in text:
            problems.append(f"{PROFILE_SOURCE}: no candidate is named {name}")
    eta = re.search(r"^pub const ERROR_ETA: u32 = (\d+);", (root / COINS_SOURCE).read_text(), re.M)
    if eta is None or int(eta.group(1)) != ERROR_ETA:
        problems.append(f"{COINS_SOURCE}: ERROR_ETA differs from {ERROR_ETA}")
    return problems


def parameters_of(name, shape, instance):
    """The LWE instance `instance` of a profile and its description."""
    modulus, samples = instance.split(":")
    main_modulus, special_modulus = moduli(shape)
    q = main_modulus * special_modulus if modulus == "QP" else main_modulus
    n = ZZ(1) << shape[0]
    parameters = LWE.Parameters(
        n=n,
        q=q,
        Xs=ND.Uniform(ZZ(-1), ZZ(1)),
        Xe=ND.CenteredBinomial(ZZ(ERROR_ETA)),
        m=n if samples == "n" else oo,
        tag=f"{name}/{instance}",
    )
    described = {
        "profile": name,
        "pinned": name in PROFILES and PROFILES[name] == shape,
        "instance": instance,
        "modulus": modulus,
        "samples": samples,
        "n": int(n),
        "plaintext_modulus": int(shape[1]),
        "log2_modulus": rounded(log2_of(q), 4),
        "modulus_bits": int(q.nbits()),
        "q": str(q),
        "secret": "uniform ternary on {-1, 0, 1}",
        "error": f"centered binomial, eta = {ERROR_ETA}",
        "secret_stddev": rounded(float(parameters.Xs.stddev), 6),
        "error_stddev": rounded(float(parameters.Xe.stddev), 6),
    }
    return parameters, described


def plain(value):
    """A JSON value for one entry of a cost dictionary."""
    if isinstance(value, (str, bool)) or value is None:
        return value
    try:
        if value == oo:
            return "oo"
        real = RR(value)
    except (TypeError, ValueError, ArithmeticError):
        return str(value)
    if real.is_NaN():
        return "nan"
    if abs(real) >= 2**53:
        return {"log2": rounded(log2_of(abs(real)), 4)}
    if real == real.floor():
        return int(real)
    return float(real)


def describe(cost):
    """`log2_rop`, the estimator's own rendering and the entries of a cost dictionary."""
    rop = cost["rop"]
    if rop == oo:
        log2_rop = "oo"
    else:
        log2_rop = rounded(log2_of(rop), 4)
    entries = {str(key): plain(value) for key, value in cost.items() if key != "problem"}
    return {"log2_rop": log2_rop, "rendering": repr(cost), "cost": entries}


def run_attack(function, parameters, connection):
    """Child process: one attack on one instance; the outcome goes through `connection`."""
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        outcome = {"status": "ok"}
        outcome.update(describe(function(parameters.normalize())))
        message = json.dumps(outcome, allow_nan=False)
    except Exception as error:  # the outcome records what the estimator raised
        message = json.dumps({"status": "error", "message": f"{type(error).__name__}: {error}"})
    connection.send(message)
    connection.close()


def resident_gib(pids):
    """Resident set size of each process in GiB, by `ps`; a process that is gone is absent."""
    if not pids:
        return {}
    listing = subprocess.run(
        ["ps", "-o", "pid=,rss=", "-p", ",".join(str(pid) for pid in pids)],
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    out = {}
    for line in listing.splitlines():
        fields = line.split()
        if len(fields) == 2:
            out[int(fields[0])] = int(fields[1]) / float(2**20)
    return out


def emit(kind, record):
    print(kind + " " + json.dumps(record, sort_keys=True, allow_nan=False), flush=True)


STOP = {"requested": False}


def request_stop(_signal_number, _frame):
    STOP["requested"] = True


def run_tasks(tasks, parallel, timeout, memory_limit_gib):
    """Run each (identity, parameters, function) in a process of its own; print a RESULT per task.

    SIGTERM or SIGINT stops the run: every attack that is running or has not
    started then gets a RESULT that says so.
    """
    context = multiprocessing.get_context("fork")
    pending = list(tasks)
    running = []
    counts = {}
    last_memory_check = 0.0

    def report(identity, outcome, seconds, peak):
        record = dict(identity)
        record.update(outcome)
        record["seconds"] = rounded(seconds, 1)
        record["peak_resident_gib"] = rounded(peak, 2)
        counts[record["status"]] = counts.get(record["status"], 0) + 1
        label = "{profile}/{instance} {model} {attack}".format(**record)
        print(f"{label} :: {record.get('rendering', record.get('message'))}", flush=True)
        emit("RESULT", record)

    def stop(entry, status, message):
        entry["process"].kill()
        entry["process"].join()
        return {"status": status, "message": message}

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    try:
        while pending or running:
            if STOP["requested"]:
                for entry in running:
                    elapsed = time.time() - entry["started"]
                    outcome = stop(entry, "stopped", f"the run was stopped {int(elapsed)} seconds into this attack")
                    report(entry["identity"], outcome, elapsed, entry["peak"])
                running = []
                for identity, _parameters, _function in pending:
                    outcome = {"status": "not_started", "message": "the run was stopped before this attack started"}
                    report(identity, outcome, 0, 0)
                pending = []
                break
            while pending and len(running) < parallel:
                identity, parameters, function = pending.pop(0)
                receiver, sender = context.Pipe(duplex=False)
                process = context.Process(target=run_attack, args=(function, parameters, sender))
                process.start()
                sender.close()
                running.append(
                    {"identity": identity, "process": process, "receiver": receiver, "started": time.time(), "peak": 0}
                )
            now = time.time()
            if now - last_memory_check >= 5:
                last_memory_check = now
                usage = resident_gib([entry["process"].pid for entry in running])
                for entry in running:
                    entry["peak"] = max(entry["peak"], usage.get(entry["process"].pid, 0))
            still_running = []
            for entry in running:
                process, receiver = entry["process"], entry["receiver"]
                elapsed = time.time() - entry["started"]
                outcome = None
                if receiver.poll():
                    try:
                        outcome = json.loads(receiver.recv())
                    except EOFError:
                        outcome = {"status": "error", "message": "the attack process closed its pipe without a result"}
                    process.join()
                elif not process.is_alive():
                    process.join()
                    outcome = {"status": "error", "message": f"the attack process exited with status {process.exitcode}"}
                elif elapsed > timeout:
                    outcome = stop(entry, "timeout", f"stopped at the limit of {int(timeout)} seconds")
                elif entry["peak"] > memory_limit_gib:
                    outcome = stop(
                        entry,
                        "memory_limit",
                        f"stopped above the resident-memory limit of {float(memory_limit_gib):g} GiB",
                    )
                if outcome is None:
                    still_running.append(entry)
                    continue
                receiver.close()
                report(entry["identity"], outcome, elapsed, entry["peak"])
            running = still_running
            if running:
                time.sleep(float(1) / 5)
    finally:
        for entry in running:
            if entry["process"].is_alive():
                entry["process"].kill()
    return counts


def self_check():
    """Compare the per-attack calls of this script with `LWE.estimate` on Kyber512."""
    agree = True
    for model_name, model in MODELS.items():
        reference = LWE.estimate(Kyber512, red_cost_model=model, quiet=True)
        attacks = dict(model_free_attacks())
        attacks.update(lattice_attacks(model))
        for attack, function in attacks.items():
            expected = reference.get(attack)
            note = "LWE.estimate has none"
            try:
                found = function(Kyber512.normalize())
            except Exception as error:  # `LWE.estimate` drops an attack that raises
                found = None
                note = f"this script: {type(error).__name__}"
            if expected is None or found is None:
                same = expected is None and found is None
                detail = "no result from either" if same else f"only one of the two returned a result ({note})"
            else:
                same = describe(expected) == describe(found)
                detail = repr(found)
            agree = agree and same
            print(f"self-check Kyber512 {model_name} {attack}: {'equal' if same else 'DIFFERENT'} :: {detail}", flush=True)
    emit("SELFCHECK", {"parameters": "Kyber512", "equal_to_LWE_estimate": agree})
    return agree


def host_description():
    def sysctl(name):
        try:
            return subprocess.run(["sysctl", "-n", name], capture_output=True, text=True, check=False).stdout.strip()
        except OSError:
            return ""

    host = {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "logical_cpus": int(os.cpu_count() or 0),
        "load_average_1m": rounded(float(os.getloadavg()[0]), 2),
    }
    if platform.system() == "Darwin":
        host["model"] = sysctl("hw.model")
        host["cpu"] = sysctl("machdep.cpu.brand_string")
        host["physical_memory_bytes"] = int(sysctl("hw.memsize") or 0)
    return host


def home_relative(path):
    """`path` with the home directory written as `~`."""
    home = str(Path.home())
    text = str(path)
    return "~" + text[len(home):] if text.startswith(home) else text


def estimator_commit():
    """The commit of the estimator checkout that was imported, or "unknown"."""
    checkout = Path(estimator.__file__).resolve().parent.parent
    try:
        found = subprocess.run(
            ["git", "-C", str(checkout), "rev-parse", "HEAD"], capture_output=True, text=True, check=False
        )
    except OSError:
        return checkout, "unknown"
    return checkout, found.stdout.strip() if found.returncode == 0 else "unknown"


def code_sha256():
    """SHA-256 of this script from the end of its leading comment block: the code a run executed."""
    source = SOURCE.with_name(SOURCE.name[: -len(".py")]) if SOURCE.name.endswith(".sage.py") else SOURCE
    lines = source.read_text().splitlines(keepends=True)
    start = next(index for index, line in enumerate(lines) if not line.startswith("#"))
    return hashlib.sha256("".join(lines[start:]).encode()).hexdigest()


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def shape_argument(text):
    """`LOG_N,T,MAIN_BITS,MAIN_COUNT,SPECIAL_BITS,SPECIAL_COUNT` as a named shape."""
    fields = [int(item) for item in text.split(",")]
    if len(fields) != 6 or min(fields) < 1:
        raise argparse.ArgumentTypeError("expected six positive integers")
    log_degree, plaintext, main_bits, main_count, special_bits, special_count = fields
    name = f"bgv.derive.n{log_degree}.t{plaintext}.q{main_count}x{main_bits}.p{special_count}x{special_bits}"
    return name, (log_degree, plaintext, (main_bits, main_count), (special_bits, special_count))


def main(argv):
    parser = argparse.ArgumentParser(
        prog="sage scripts/fhe_bgv_lattice_estimator.sage",
        description="Lattice Estimator costs of the iroha_fhe RNS-BGV profiles (a raw record on standard output).",
    )
    parser.add_argument("--profile", action="append", choices=sorted(PROFILES), help="pinned profile (default: all)")
    parser.add_argument(
        "--shape",
        action="append",
        type=shape_argument,
        default=[],
        metavar="LOG_N,T,MAIN_BITS,MAIN_COUNT,SPECIAL_BITS,SPECIAL_COUNT",
        help="a parameter set outside the pinned list, derived by the first-prime rule; with it, pinned"
        " profiles run only when --profile names them",
    )
    parser.add_argument("--instance", action="append", choices=INSTANCES, help="LWE instance (default: all)")
    parser.add_argument(
        "--model", action="append", choices=list(MODELS) + [MODEL_FREE], help="reduction cost model (default: all)"
    )
    parser.add_argument(
        "--attack",
        action="append",
        choices=LATTICE_ATTACKS + MODEL_FREE_ATTACKS,
        help="attack (default: all)",
    )
    parser.add_argument("--timeout", type=int, default=3600, help="seconds allowed per attack (default: 3600)")
    parser.add_argument(
        "--memory-limit-gib", type=float, default=8.0, help="resident memory allowed per attack (default: 8)"
    )
    parser.add_argument("--parallel", type=int, default=1, help="attacks run at once (default: 1)")
    parser.add_argument(
        "--self-check",
        action="store_true",
        help="compare the per-attack calls with LWE.estimate on Kyber512 and exit",
    )
    parser.add_argument("--list", action="store_true", help="print the selected estimates and exit")
    arguments = parser.parse_args(argv)
    if arguments.timeout < 1 or arguments.parallel < 1 or arguments.memory_limit_gib <= 0:
        parser.error("--timeout, --parallel and --memory-limit-gib must be positive")

    shapes = {}
    if arguments.profile or not arguments.shape:
        for name in arguments.profile or PROFILES:
            shapes[name] = PROFILES[name]
    for name, shape in arguments.shape:
        shapes[name] = shape
    instances = arguments.instance or INSTANCES
    models = arguments.model or list(MODELS) + [MODEL_FREE]
    selected = arguments.attack or LATTICE_ATTACKS + MODEL_FREE_ATTACKS

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    script = sys.argv[0][: -len(".py")] if sys.argv[0].endswith(".sage.py") else sys.argv[0]
    checkout, commit = estimator_commit()
    started = time.time()
    print("# Output of scripts/fhe_bgv_lattice_estimator.sage: Lattice Estimator costs of iroha_fhe RNS-BGV profiles.")
    print("# A raw record; do not edit. RUN, INSTANCE, RESULT, SELFCHECK and END lines carry one JSON object each.")
    emit(
        "RUN",
        {
            "sagemath": version(),
            "python": platform.python_version(),
            "interpreter": home_relative(sys.executable),
            "estimator_checkout": home_relative(checkout),
            "estimator_commit": commit,
            "estimator_commit_expected": ESTIMATOR_COMMIT,
            "script_code_sha256": code_sha256(),
            "command": " ".join(
                ["PYTHONPATH=" + home_relative(checkout), "sage", script] + [str(item) for item in argv]
            ),
            "started_utc": utc_now(),
            "host": host_description(),
            "timeout_seconds": int(arguments.timeout),
            "memory_limit_gib": float(arguments.memory_limit_gib),
            "parallel": int(arguments.parallel),
        },
    )
    if commit != ESTIMATOR_COMMIT:
        print(f"the estimator checkout is at {commit}, not at the pinned {ESTIMATOR_COMMIT}", file=sys.stderr)
        return 1
    problems = source_problems(ROOT)
    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        return 1
    print(
        f"source check: the first-prime rule gives the pinned primes of {PROFILE_SOURCE}"
        f" and {COINS_SOURCE} has ERROR_ETA = {ERROR_ETA}"
    )

    if arguments.self_check:
        agree = self_check()
        emit("END", {"finished_utc": utc_now(), "wall_seconds": rounded(float(time.time() - started), 1)})
        return 0 if agree else 1

    tasks = []
    for name, shape in shapes.items():
        main_modulus, special_modulus = moduli(shape)
        print(
            f"=== {name}: n = 2^{shape[0]}, t = {shape[1]},"
            f" log2 Q = {log2_of(main_modulus):.4f},"
            f" log2 QP = {log2_of(main_modulus * special_modulus):.4f}"
        )
        for instance in instances:
            parameters, described = parameters_of(name, shape, instance)
            emit("INSTANCE", described)
            identity = {key: described[key] for key in ("profile", "pinned", "instance", "modulus", "samples", "n", "log2_modulus")}
            for model_name in models:
                if model_name == MODEL_FREE:
                    attacks = model_free_attacks()
                else:
                    attacks = lattice_attacks(MODELS[model_name])
                for attack, function in attacks.items():
                    if attack in selected:
                        tasks.append((dict(identity, model=model_name, attack=attack), parameters, function))
    # Cheap attacks first, then profiles, cost models and instances in their listed order, so
    # that a record that is cut short holds as much as possible.
    attack_order = ("usvp", "dual", "dual_hybrid", "bdd", "bdd_hybrid", "bdd_mitm_hybrid", "arora-gb", "bkw")
    profile_order = list(shapes)
    model_order = list(MODELS) + [MODEL_FREE]
    instance_order = ("QP:n", "QP:oo", "Q:n")
    tasks.sort(
        key=lambda task: (
            attack_order.index(task[0]["attack"]),
            profile_order.index(task[0]["profile"]),
            model_order.index(task[0]["model"]),
            instance_order.index(task[0]["instance"]),
        )
    )
    if arguments.list:
        for identity, _parameters, _function in tasks:
            print("{profile}/{instance} {model} {attack}".format(**identity))
        return 0
    counts = run_tasks(tasks, arguments.parallel, arguments.timeout, arguments.memory_limit_gib)
    emit(
        "END",
        {
            "finished_utc": utc_now(),
            "wall_seconds": rounded(float(time.time() - started), 1),
            "results": int(sum(counts.values())),
            "by_status": {key: int(value) for key, value in sorted(counts.items())},
        },
    )
    return 0


if __name__ == "__main__":
    # `int`: under the preparser a literal status is a Sage integer, which Python reports as an error.
    raise SystemExit(int(main(sys.argv[1:])))
