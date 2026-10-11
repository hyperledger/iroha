"""Bounded Laurent-polynomial controls for the native non-hiding IPA recurrence.

These are finite algebra checks, not a transcript model or a proof of privacy.
Variables are alpha, z, zeta, followed by the round challenges in native order.
"""

from math import prod


class Ring:
    """Sparse integer or finite-characteristic Laurent polynomials."""

    def __init__(self, variables, modulus=None):
        self.variables = variables
        self.modulus = modulus

    def clean(self, terms):
        """Reduce coefficients and remove zero terms without changing exponents."""
        if self.modulus is not None:
            terms = {e: c % self.modulus for e, c in terms.items()}
        return {e: c for e, c in terms.items() if c}

    def constant(self, value):
        """Embed a constant, including canonical zero."""
        return self.clean({(0,) * self.variables: value})

    def variable(self, index, power=1):
        """One variable's integer power; negative powers model inverses."""
        exponents = [0] * self.variables
        exponents[index] = power
        return {tuple(exponents): 1}

    def add(self, *polynomials):
        """Add polynomials without aliasing any operand."""
        result = {}
        for polynomial in polynomials:
            for exponent, coefficient in polynomial.items():
                result[exponent] = result.get(exponent, 0) + coefficient
        return self.clean(result)

    def multiply(self, *polynomials):
        """Multiply sparse polynomials, collecting equal Laurent monomials."""
        result = self.constant(1)
        for polynomial in polynomials:
            terms = {}
            for left, a in result.items():
                for right, b in polynomial.items():
                    exponent = tuple(x + y for x, y in zip(left, right))
                    terms[exponent] = terms.get(exponent, 0) + a * b
            result = self.clean(terms)
        return result

    def inner(self, left, right):
        """Inner product, refusing a truncated zip."""
        if len(left) != len(right):
            raise ValueError("inner-product lengths differ")
        return self.add(*(self.multiply(a, b) for a, b in zip(left, right)))

    def coefficient(self, polynomial, variable, power):
        """Extract one coefficient as a polynomial in the remaining variables."""
        return {e[:variable] + (0,) + e[variable + 1:]: c
                for e, c in polynomial.items() if e[variable] == power}

    def degree(self, polynomial):
        """Total degree after checking that every denominator was cleared."""
        if any(min(exponent) < 0 for exponent in polynomial):
            raise ValueError("uncleared Laurent denominator")
        return max((sum(e) for e in polynomial), default=-1)

    def evaluate(self, polynomial, values):
        """Evaluate over the selected finite field with explicit inverses."""
        if self.modulus is None or len(values) != self.variables:
            raise ValueError("finite-characteristic evaluation needs every variable")
        return sum(c * prod(pow(value, exponent, self.modulus)
                            for value, exponent in zip(values, powers))
                   for powers, c in polynomial.items()) % self.modulus


def abort_coefficient(k, inputs):
    """Numerator of the independent-tape encoding/zero-event union bound."""
    if type(k) is not int or not 1 <= k <= 16:
        raise ValueError("supported mathematical fold depth is 1..16")
    if type(inputs) is not int or inputs < 1:
        raise ValueError("positive ordered input count required")
    return 2 * k * (inputs - 1) + 2 * k * k + (3 * k - 2) * (1 << k) + 2


def recurrence(k, sources, generator_logs, auxiliary_log=1, modulus=None):
    """Expand at most four rounds/inputs, retaining each denominator-cleared point.

    Source challenges use their actual short width and occupy the low coefficient
    prefix. A short-only input is deliberately permitted for the negative control.
    Logs describe a cyclic additive group; no log independence is assumed.
    """
    if type(k) is not int or not 1 <= k <= 4 or not 1 <= len(sources) <= 4:
        raise ValueError("bounded control permits k=1..4 and one to four inputs")
    n = 1 << k
    if len(generator_logs) != n or not auxiliary_log:
        raise ValueError("complete generators and a nonzero auxiliary log required")
    if any(len(source) > k or any(not value for value in source) for source in sources):
        raise ValueError("nonzero source challenges with width at most k required")
    if modulus is not None and (modulus < 2 or
            any(value % modulus == 0 for source in sources for value in source) or
            any(value % modulus == 0 for value in [*generator_logs, auxiliary_log])):
        raise ValueError("all serialized input challenges and generators must be nonzero")
    if any(not value for value in generator_logs):
        raise ValueError("nonzero generator logs required")
    ring = Ring(k + 3, modulus)
    alpha, zeta = ring.variable(0), ring.variable(2)
    original = [ring.constant(0) for _ in range(n)]
    weight = ring.constant(1)
    for source in sources:
        # Bit-product definition is independent of the native doubling loop.
        for index in range(1 << len(source)):
            value = prod(challenge for bit, challenge in enumerate(source)
                         if index & (1 << (len(source) - bit - 1)))
            original[index] = ring.add(original[index], ring.multiply(weight, ring.constant(value)))
        weight = ring.multiply(weight, alpha)
    powers = [ring.variable(1, i) for i in range(n)]
    coefficients = original.copy()
    coefficients[0] = ring.add(coefficients[0],
                               ring.multiply(ring.constant(-1), ring.inner(original, powers)))
    generators = [ring.constant(value) for value in generator_logs]
    denominator = ring.constant(1)
    rounds = []
    for j in range(k):
        half = len(coefficients) // 2
        left_aux = ring.inner(coefficients[half:], powers[:half])
        right_aux = ring.inner(coefficients[:half], powers[half:])
        left = ring.add(ring.inner(coefficients[half:], generators[:half]),
                        ring.multiply(zeta, ring.constant(auxiliary_log), left_aux))
        right = ring.add(ring.inner(coefficients[:half], generators[half:]),
                         ring.multiply(zeta, ring.constant(auxiliary_log), right_aux))
        rounds.append({"left": ring.multiply(denominator, left),
                       "right": ring.multiply(denominator, right),
                       "left_aux": ring.multiply(denominator, left_aux),
                       "right_aux": ring.multiply(denominator, right_aux),
                       "last_a": ring.multiply(denominator, coefficients[-1]),
                       "denominator": denominator, "half": half})
        challenge = ring.variable(j + 3)
        inverse = ring.variable(j + 3, -1)
        coefficients = [ring.add(a, ring.multiply(inverse, b))
                        for a, b in zip(coefficients[:half], coefficients[half:])]
        powers = [ring.add(a, ring.multiply(challenge, b))
                  for a, b in zip(powers[:half], powers[half:])]
        generators = [ring.add(a, ring.multiply(challenge, b))
                      for a, b in zip(generators[:half], generators[half:])]
        denominator = ring.multiply(denominator, challenge)
    return ring, original, rounds, generators[0]
