# Lattice Estimator invocation for the iroha_fhe RNS-BGV starting candidates.
#
# STATUS: NOT RUN. SageMath was not installed on the host that produced
# specs/fhe_bgv_cost_summary.json, and nothing was installed for task C.3. Until
# this script has been run and its output reviewed, no candidate has a security
# estimate; the core-SVP numbers in the summary are a sanity calculation and
# not a substitute.
#
# How to run (on a host with SageMath >= 10):
#
#   git clone https://github.com/malb/lattice-estimator
#   git -C lattice-estimator checkout 53da5982597709ba0fdf94ea37a84d822310fd84
#   PYTHONPATH=lattice-estimator sage scripts/fhe_bgv_lattice_estimator.sage
#
# The pinned commit is the head of the estimator's main branch on 2026-10-05.
# Record the complete output next to the summary and change
# `security_estimate.lattice_estimator.status` only together with it.
#
# What is estimated
# -----------------
# Every published object of the scheme is a ring-LWE sample in
# Z_q[X]/(X^N + 1):
#
# * the public key and fresh ciphertexts, modulo Q = q_0 * ... * q_L;
# * the relinearization and Galois keys, modulo Q * P.
#
# The largest modulus Q * P governs. Samples have the form b = -a*s + t*e
# with gcd(t, q) = 1, so multiplying by t^-1 yields ordinary samples with
# error e: the error distribution of the estimate is that of e, not of t*e.
#
# * secret: uniform ternary (each coefficient -1, 0, 1 with probability 1/3);
# * error: centered binomial with eta = 21 (support [-21, 21], variance 10.5);
# * dimension n = N; the estimator treats ring-LWE as LWE of that dimension,
#   which ignores the ring structure;
# * samples: m = n per published polynomial; a key set publishes the public
#   key plus digits * (1 + Galois keys) switching-key polynomials. The
#   estimate is run with m = n and with unlimited samples (m = oo).
#
# Attacks and cost models: LWE.estimate runs the primal uSVP, primal BDD,
# primal hybrid, dual and dual hybrid attacks. It is run under RC.BDGL16
# (classical) and under RC.ADPS16 in classical and quantum mode. The target
# recorded by the plan's design memo is at least 128 bits classically, with
# quantum costs reported separately.
#
# Not covered by this script: the circular-security (key-dependent message)
# assumption of publishing encryptions of s^2 and s(X^k) under s; any use of
# the ring structure; malicious keys or ciphertexts; side channels.

# This file has never been executed. If a name below differs at the pinned
# commit, correct the call, never the parameters.

from estimator import LWE, ND, RC
from estimator.reduction import ADPS16
from sage.all import Primes, log, oo, prod

ESTIMATOR_COMMIT = "53da5982597709ba0fdf94ea37a84d822310fd84"
ERROR_ETA = 21

# name: (log2 N, plaintext modulus, (main bits, main count), (special bits, special count))
PROFILES = {
    "bgv.f257.n14.q6x50.p2x60": (14, 257, (50, 6), (60, 2)),
    "bgv.f257.n16.q22x50.p2x60": (16, 257, (50, 22), (60, 2)),
    "bgv.f257.n16.q32x50.p2x60": (16, 257, (50, 32), (60, 2)),
    # The measured fully splitting comparator; not a RAM-LFE candidate.
    "bgv.derive.n16.t786433.q25x60.p3x60.d2": (16, 786433, (60, 25), (60, 3)),
}


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


def moduli(log_degree, plaintext, main, special):
    step = 2 * (1 << log_degree) * plaintext
    main_primes = first_primes(main[0], step, main[1])
    special_primes = first_primes(special[0], step, special[1], tuple(main_primes))
    return prod(main_primes), prod(special_primes)


def estimate(name, log_degree, q, samples):
    n = 1 << log_degree
    parameters = LWE.Parameters(
        n=n,
        q=q,
        Xs=ND.Uniform(-1, 1),
        Xe=ND.CenteredBinomial(ERROR_ETA),
        m=samples,
        tag=name,
    )
    print(parameters)
    for label, model in (
        ("BDGL16 classical", RC.BDGL16),
        ("ADPS16 classical", RC.ADPS16),
    ):
        print(f"--- {name}, m = {samples}, {label}")
        LWE.estimate(parameters, red_cost_model=model)
    print(f"--- {name}, m = {samples}, ADPS16 quantum")
    LWE.estimate(parameters, red_cost_model=ADPS16(mode="quantum"))


print(f"lattice-estimator commit expected: {ESTIMATOR_COMMIT}")
for name, (log_degree, plaintext, main, special) in PROFILES.items():
    main_modulus, special_modulus = moduli(log_degree, plaintext, main, special)
    print(
        f"=== {name}: n = 2^{log_degree}, log2 Q = {float(log(main_modulus, 2)):.2f},"
        f" log2 QP = {float(log(main_modulus * special_modulus, 2)):.2f}"
    )
    n = 1 << log_degree
    # Fresh ciphertexts and the public key: modulus Q.
    estimate(name + "/Q", log_degree, main_modulus, n)
    # Switching keys: modulus Q * P, with n samples and with unlimited samples.
    estimate(name + "/QP", log_degree, main_modulus * special_modulus, n)
    estimate(name + "/QP", log_degree, main_modulus * special_modulus, oo)
