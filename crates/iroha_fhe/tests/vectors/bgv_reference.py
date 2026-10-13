#!/usr/bin/env python3
"""Independent reference of the iroha_fhe RNS-BGV scheme and generator of its known answers.

Python 3.9+ and its standard library only. This file shares no code with the
Rust implementation: it works on arbitrary-precision integers modulo the full
modulus (never on residues), multiplies polynomials by the schoolbook rule,
reconstructs residue polynomials with the constructive Chinese remainder
formula, and carries its own implementation of the BLAKE3 `derive_key`
extendable output for inputs of at most one chunk.

Usage:
    python3 crates/iroha_fhe/tests/vectors/bgv_reference.py            # print the vectors
    python3 crates/iroha_fhe/tests/vectors/bgv_reference.py --write    # rewrite bgv_kat_v1.txt
    python3 crates/iroha_fhe/tests/vectors/bgv_reference.py --check    # fail when the file differs

`crates/iroha_fhe/tests/bgv_vectors.rs` reads the generated file and requires
the Rust implementation to produce every word of it from the same seed.
"""

from __future__ import annotations

import sys
from pathlib import Path

KAT_FILE = Path(__file__).with_name("bgv_kat_v1.txt")

# ---------------------------------------------------------------------------
# BLAKE3 derive_key with extendable output, single chunk (input <= 1024 bytes)
# ---------------------------------------------------------------------------

MASK32 = 0xFFFFFFFF
IV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
MSG_PERMUTATION = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]
CHUNK_START, CHUNK_END, ROOT = 1, 2, 8
DERIVE_KEY_CONTEXT, DERIVE_KEY_MATERIAL = 32, 64


def _rotr(value: int, shift: int) -> int:
    return ((value >> shift) | (value << (32 - shift))) & MASK32


def _g(state: list[int], a: int, b: int, c: int, d: int, mx: int, my: int) -> None:
    state[a] = (state[a] + state[b] + mx) & MASK32
    state[d] = _rotr(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & MASK32
    state[b] = _rotr(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b] + my) & MASK32
    state[d] = _rotr(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & MASK32
    state[b] = _rotr(state[b] ^ state[c], 7)


def _compress(cv: list[int], block: list[int], counter: int, block_len: int, flags: int) -> list[int]:
    state = cv[:8] + IV[:4] + [counter & MASK32, (counter >> 32) & MASK32, block_len, flags]
    words = list(block)
    for round_index in range(7):
        _g(state, 0, 4, 8, 12, words[0], words[1])
        _g(state, 1, 5, 9, 13, words[2], words[3])
        _g(state, 2, 6, 10, 14, words[4], words[5])
        _g(state, 3, 7, 11, 15, words[6], words[7])
        _g(state, 0, 5, 10, 15, words[8], words[9])
        _g(state, 1, 6, 11, 12, words[10], words[11])
        _g(state, 2, 7, 8, 13, words[12], words[13])
        _g(state, 3, 4, 9, 14, words[14], words[15])
        if round_index < 6:
            words = [words[MSG_PERMUTATION[index]] for index in range(16)]
    for index in range(8):
        state[index] ^= state[index + 8]
        state[index + 8] ^= cv[index]
    return state


def _block_words(block: bytes) -> list[int]:
    padded = block + bytes(64 - len(block))
    return [int.from_bytes(padded[4 * index : 4 * index + 4], "little") for index in range(16)]


class _Output:
    """The root output of a single-chunk hash; `read` yields the extendable output."""

    def __init__(self, key_words: list[int], data: bytes, flags: int) -> None:
        if len(data) > 1024:
            raise ValueError("this reference hashes at most one 1024-byte chunk")
        blocks = [data[offset : offset + 64] for offset in range(0, len(data), 64)] or [b""]
        cv = list(key_words)
        for index, block in enumerate(blocks[:-1]):
            block_flags = flags | (CHUNK_START if index == 0 else 0)
            cv = _compress(cv, _block_words(block), 0, 64, block_flags)[:8]
        last_flags = flags | CHUNK_END | (CHUNK_START if len(blocks) == 1 else 0)
        self._cv = cv
        self._block = _block_words(blocks[-1])
        self._block_len = len(blocks[-1])
        self._flags = last_flags | ROOT
        self._buffer = b""
        self._counter = 0

    def read(self, count: int) -> bytes:
        while len(self._buffer) < count:
            words = _compress(self._cv, self._block, self._counter, self._block_len, self._flags)
            self._buffer += b"".join(word.to_bytes(4, "little") for word in words)
            self._counter += 1
        out, self._buffer = self._buffer[:count], self._buffer[count:]
        return out


def derive_key_xof(context: str, material: bytes) -> _Output:
    context_key = _Output(IV, context.encode(), DERIVE_KEY_CONTEXT).read(32)
    key_words = [int.from_bytes(context_key[4 * index : 4 * index + 4], "little") for index in range(8)]
    return _Output(key_words, material, DERIVE_KEY_MATERIAL)


# ---------------------------------------------------------------------------
# Number theory
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


def first_primes(bits: int, step: int, count: int, skip: tuple[int, ...] = ()) -> list[int]:
    """The first `count` primes of exactly `bits` bits congruent to one modulo `step`."""
    out: list[int] = []
    candidate = ((1 << (bits - 1)) // step + 1) * step + 1
    while len(out) < count:
        if candidate >= 1 << bits:
            raise ValueError("no prime of the requested size")
        if is_prime(candidate) and candidate not in skip:
            out.append(candidate)
        candidate += step
    return out


def root_of_order(prime: int, order: int) -> int:
    """`g^((prime - 1) / order)` for the smallest `g >= 2` that makes it primitive."""
    exponent = (prime - 1) // order
    for generator in range(2, 1 << 16):
        root = pow(generator, exponent, prime)
        if pow(root, order // 2, prime) == prime - 1:
            return root
    raise ValueError("no root")


def product(values) -> int:
    out = 1
    for value in values:
        out *= value
    return out


def centered(value: int, modulus: int) -> int:
    value %= modulus
    return value - modulus if value > (modulus - 1) // 2 else value


def crt(residues: list[int], primes: list[int]) -> int:
    """The constructive Chinese remainder formula."""
    modulus = product(primes)
    total = 0
    for residue, prime in zip(residues, primes):
        partial = modulus // prime
        total += residue * partial * pow(partial, -1, prime)
    return total % modulus


# ---------------------------------------------------------------------------
# Ring arithmetic on integer coefficient lists
# ---------------------------------------------------------------------------


def poly_mul(lhs: list[int], rhs: list[int], modulus: int) -> list[int]:
    degree = len(lhs)
    out = [0] * degree
    for i, a in enumerate(lhs):
        if a == 0:
            continue
        for j, b in enumerate(rhs):
            if i + j >= degree:
                out[i + j - degree] -= a * b
            else:
                out[i + j] += a * b
    return [value % modulus for value in out]


def poly_add(lhs: list[int], rhs: list[int], modulus: int) -> list[int]:
    return [(a + b) % modulus for a, b in zip(lhs, rhs)]


def poly_sub(lhs: list[int], rhs: list[int], modulus: int) -> list[int]:
    return [(a - b) % modulus for a, b in zip(lhs, rhs)]


def poly_scale(poly: list[int], scalar: int, modulus: int) -> list[int]:
    return [value * scalar % modulus for value in poly]


def poly_automorphism(poly: list[int], power: int) -> list[int]:
    """The image under X -> X^power over the integers (signs kept)."""
    degree = len(poly)
    out = [0] * degree
    for index, value in enumerate(poly):
        exponent = index * power % (2 * degree)
        if exponent >= degree:
            out[exponent - degree] -= value
        else:
            out[exponent] += value
    return out


# ---------------------------------------------------------------------------
# Profile
# ---------------------------------------------------------------------------

PROFILE_IDENTITY_CONTEXT = "iroha_fhe bgv v1 profile identity"
COIN_STREAM_CONTEXT = "iroha_fhe bgv v1 coin stream"
FIXTURE_ENTROPY_CONTEXT = "iroha_fhe bgv v1 fixture entropy"
(
    SECRET_KEY,
    PUBLIC_KEY_MASK,
    PUBLIC_KEY_ERROR,
    ENCRYPTION_MASK,
    ENCRYPTION_ERROR0,
    ENCRYPTION_ERROR1,
    SWITCHING_KEY_MASK,
    SWITCHING_KEY_ERROR,
) = range(1, 9)


class Profile:
    def __init__(self, log_degree, plaintext, main_bits, main_count, special_bits, special_count, digit_primes, eta=21):
        self.log_degree = log_degree
        self.degree = 1 << log_degree
        self.t = plaintext
        step = 2 * self.degree * plaintext
        self.main = first_primes(main_bits, step, main_count)
        self.special = first_primes(special_bits, step, special_count, tuple(self.main))
        self.main_roots = [root_of_order(prime, 2 * self.degree) for prime in self.main]
        self.special_roots = [root_of_order(prime, 2 * self.degree) for prime in self.special]
        self.digit_primes = digit_primes
        self.eta = eta
        self.top = len(self.main) - 1
        self.special_product = product(self.special)

    def canonical_bytes(self) -> bytes:
        out = bytes([1]) + self.log_degree.to_bytes(4, "little") + self.t.to_bytes(8, "little")
        for primes, roots in ((self.main, self.main_roots), (self.special, self.special_roots)):
            out += len(primes).to_bytes(4, "little")
            for prime, root in zip(primes, roots):
                out += prime.to_bytes(8, "little") + root.to_bytes(8, "little")
        out += bytes([1]) + self.digit_primes.to_bytes(4, "little")
        out += bytes([1, 1, 1]) + self.eta.to_bytes(4, "little") + bytes([1])
        return out

    def identity(self) -> bytes:
        return derive_key_xof(PROFILE_IDENTITY_CONTEXT, self.canonical_bytes()).read(32)

    def modulus(self, level: int) -> int:
        return product(self.main[: level + 1])

    def digits(self, level: int) -> list[list[int]]:
        """The digit groups present at `level`, as lists of main-prime indices."""
        groups = []
        first = 0
        while first <= level:
            groups.append(list(range(first, min(first + self.digit_primes, level + 1))))
            first += self.digit_primes
        return groups

    # Public noise bounds -------------------------------------------------

    def fresh_noise(self) -> int:
        return (self.t - 1) // 2 + self.t * self.eta * (2 * self.degree + 1)

    def key_switch_noise(self, level: int) -> int:
        halves = sum(product(self.main[i] for i in group) // 2 for group in self.digits(level))
        p = self.special_product
        numerator = self.t * self.degree * self.eta * halves + self.t * ((p - 1) // 2) * (1 + self.degree)
        return numerator // p

    def switch_down_noise(self, bound: int, level: int) -> int:
        q = self.main[level]
        return (bound + self.t * ((q - 1) // 2) * (1 + self.degree)) // q

    def capacity(self, level: int) -> int:
        return (self.modulus(level) - 1) // 2


def fixture_seed(master: bytes, index: int) -> bytes:
    return derive_key_xof(FIXTURE_ENTROPY_CONTEXT, master + index.to_bytes(4, "little")).read(64)


def coin_stream(profile: Profile, seed: bytes, purpose: int, key_tag: int = 0, digit: int = 0) -> _Output:
    material = profile.identity() + bytes([purpose]) + key_tag.to_bytes(4, "little") + digit.to_bytes(4, "little") + seed
    return derive_key_xof(COIN_STREAM_CONTEXT, material)


def sample_ternary(stream: _Output, count: int) -> list[int]:
    out = []
    while len(out) < count:
        byte = stream.read(1)[0]
        if byte != 255:
            out.append(byte % 3 - 1)
    return out


def sample_error(stream: _Output, eta: int, count: int) -> list[int]:
    mask = (1 << eta) - 1
    out = []
    for _ in range(count):
        bits = int.from_bytes(stream.read(6), "little")
        out.append(bin(bits & mask).count("1") - bin((bits >> eta) & mask).count("1"))
    return out


def sample_uniform(stream: _Output, primes: list[int], degree: int) -> list[list[int]]:
    """One residue vector per prime, limb by limb."""
    limbs = []
    for prime in primes:
        mask = (1 << prime.bit_length()) - 1
        limb = []
        while len(limb) < degree:
            candidate = int.from_bytes(stream.read(8), "little") & mask
            if candidate < prime:
                limb.append(candidate)
        limbs.append(limb)
    return limbs


def lift(limbs: list[list[int]], primes: list[int]) -> list[int]:
    """Residue vectors to integer coefficients modulo the product."""
    return [crt([limb[index] for limb in limbs], primes) for index in range(len(limbs[0]))]


def words(poly: list[int], primes: list[int]) -> list[int]:
    """Limb-major canonical residues of an integer polynomial."""
    return [value % prime for prime in primes for value in poly]


# ---------------------------------------------------------------------------
# Scheme
# ---------------------------------------------------------------------------


class Keys:
    def __init__(self, profile: Profile, master: bytes, galois_elements: list[int]) -> None:
        p = profile
        n = p.degree
        top_modulus = p.modulus(p.top)
        full_primes = p.main + p.special
        full_modulus = top_modulus * p.special_product
        self.profile = p
        self.draws = 0

        def next_seed() -> bytes:
            seed = fixture_seed(master, self.draws)
            self.draws += 1
            return seed

        self.next_seed = next_seed
        seed = next_seed()
        self.secret = sample_ternary(coin_stream(p, seed, SECRET_KEY), n)
        seed = next_seed()
        self.pk_a = lift(sample_uniform(coin_stream(p, seed, PUBLIC_KEY_MASK), p.main, n), p.main)
        self.pk_e = sample_error(coin_stream(p, seed, PUBLIC_KEY_ERROR), p.eta, n)
        a_s = poly_mul(self.pk_a, self.secret, top_modulus)
        self.pk_b = [(p.t * e - x) % top_modulus for e, x in zip(self.pk_e, a_s)]
        self.switching: dict[int, list[tuple[list[int], list[int]]]] = {}
        sources = {0: poly_mul(self.secret, self.secret, full_modulus)}
        for element in galois_elements:
            sources[element] = [value % full_modulus for value in poly_automorphism(self.secret, element)]
        for tag in [0] + [element for element in galois_elements if element != 0]:
            if tag in self.switching:
                continue
            seed = next_seed()
            digits = []
            for index, group in enumerate(p.digits(p.top)):
                a = lift(sample_uniform(coin_stream(p, seed, SWITCHING_KEY_MASK, tag, index), full_primes, n), full_primes)
                e = sample_error(coin_stream(p, seed, SWITCHING_KEY_ERROR, tag, index), p.eta, n)
                digit_modulus = product(p.main[i] for i in group)
                complement = top_modulus // digit_modulus
                gadget = p.special_product * complement * pow(complement, -1, digit_modulus) % full_modulus
                a_s = poly_mul(a, self.secret, full_modulus)
                b = [
                    (p.t * err - x + gadget * src) % full_modulus
                    for err, x, src in zip(e, a_s, sources[tag])
                ]
                digits.append((b, a))
            self.switching[tag] = digits

    def encrypt(self, message: list[int]) -> "Ciphertext":
        p = self.profile
        n = p.degree
        modulus = p.modulus(p.top)
        seed = self.next_seed()
        u = sample_ternary(coin_stream(p, seed, ENCRYPTION_MASK), n)
        e0 = sample_error(coin_stream(p, seed, ENCRYPTION_ERROR0), p.eta, n)
        e1 = sample_error(coin_stream(p, seed, ENCRYPTION_ERROR1), p.eta, n)
        b_u = poly_mul(self.pk_b, u, modulus)
        a_u = poly_mul(self.pk_a, u, modulus)
        c0 = [(x + p.t * e + centered(m, p.t)) % modulus for x, e, m in zip(b_u, e0, message)]
        c1 = [(x + p.t * e) % modulus for x, e in zip(a_u, e1)]
        return Ciphertext(p, p.top, [c0, c1], p.fresh_noise())

    def inner(self, ct: "Ciphertext") -> list[int]:
        """The centered value of c0 + c1*s + c2*s^2 modulo Q_l."""
        modulus = ct.profile.modulus(ct.level)
        acc = [0] * ct.profile.degree
        power = [1] + [0] * (ct.profile.degree - 1)
        for component in ct.components:
            acc = poly_add(acc, poly_mul(component, power, modulus), modulus)
            power = poly_mul(power, [value % modulus for value in self.secret], modulus)
        return [centered(value, modulus) for value in acc]

    def decrypt(self, ct: "Ciphertext") -> list[int]:
        return [value % ct.profile.t for value in self.inner(ct)]

    def exact_noise(self, ct: "Ciphertext") -> int:
        return max(abs(value) for value in self.inner(ct))

    def key_switch(self, level: int, component: list[int], tag: int) -> tuple[list[int], list[int]]:
        p = self.profile
        level_modulus = p.modulus(level)
        special = p.special_product
        extended = level_modulus * special
        acc0 = [0] * p.degree
        acc1 = [0] * p.degree
        for group, (key_b, key_a) in zip(p.digits(level), self.switching[tag]):
            digit_modulus = product(p.main[i] for i in group)
            digit = [centered(value, digit_modulus) % extended for value in component]
            acc0 = poly_add(acc0, poly_mul(digit, [value % extended for value in key_b], extended), extended)
            acc1 = poly_add(acc1, poly_mul(digit, [value % extended for value in key_a], extended), extended)
        inverse_t = pow(p.t, -1, special)
        out = []
        for acc in (acc0, acc1):
            reduced = []
            for value in acc:
                correction = p.t * centered(value * inverse_t, special)
                quotient, remainder = divmod(value - correction, special)
                assert remainder == 0
                reduced.append(quotient % level_modulus)
            out.append(reduced)
        return out[0], out[1]


class Ciphertext:
    def __init__(self, profile: Profile, level: int, components: list[list[int]], bound: int) -> None:
        assert bound <= profile.capacity(level), "noise budget exceeded"
        self.profile = profile
        self.level = level
        self.components = components
        self.bound = bound

    def words(self) -> list[int]:
        primes = self.profile.main[: self.level + 1]
        return [word for component in self.components for word in words(component, primes)]


def add(lhs: Ciphertext, rhs: Ciphertext) -> Ciphertext:
    modulus = lhs.profile.modulus(lhs.level)
    components = [poly_add(a, b, modulus) for a, b in zip(lhs.components, rhs.components)]
    return Ciphertext(lhs.profile, lhs.level, components, lhs.bound + rhs.bound)


def sub(lhs: Ciphertext, rhs: Ciphertext) -> Ciphertext:
    modulus = lhs.profile.modulus(lhs.level)
    components = [poly_sub(a, b, modulus) for a, b in zip(lhs.components, rhs.components)]
    return Ciphertext(lhs.profile, lhs.level, components, lhs.bound + rhs.bound)


def add_plain(ct: Ciphertext, message: list[int], linf: int) -> Ciphertext:
    p = ct.profile
    modulus = p.modulus(ct.level)
    c0 = [(c + centered(m, p.t)) % modulus for c, m in zip(ct.components[0], message)]
    return Ciphertext(p, ct.level, [c0] + ct.components[1:], ct.bound + linf)


def mul_plain(ct: Ciphertext, message: list[int], l1: int) -> Ciphertext:
    p = ct.profile
    modulus = p.modulus(ct.level)
    lifted = [centered(m, p.t) % modulus for m in message]
    components = [poly_mul(component, lifted, modulus) for component in ct.components]
    return Ciphertext(p, ct.level, components, ct.bound * l1)


def tensor(lhs: Ciphertext, rhs: Ciphertext) -> Ciphertext:
    p = lhs.profile
    modulus = p.modulus(lhs.level)
    a0, a1 = lhs.components
    b0, b1 = rhs.components
    d0 = poly_mul(a0, b0, modulus)
    d1 = poly_add(poly_mul(a0, b1, modulus), poly_mul(a1, b0, modulus), modulus)
    d2 = poly_mul(a1, b1, modulus)
    return Ciphertext(p, lhs.level, [d0, d1, d2], p.degree * lhs.bound * rhs.bound)


def relinearize(keys: Keys, ct: Ciphertext) -> Ciphertext:
    p = ct.profile
    modulus = p.modulus(ct.level)
    k0, k1 = keys.key_switch(ct.level, ct.components[2], 0)
    components = [poly_add(ct.components[0], k0, modulus), poly_add(ct.components[1], k1, modulus)]
    return Ciphertext(p, ct.level, components, ct.bound + p.key_switch_noise(ct.level))


def apply_galois(keys: Keys, ct: Ciphertext, element: int) -> Ciphertext:
    p = ct.profile
    modulus = p.modulus(ct.level)
    rotated = [[value % modulus for value in poly_automorphism(component, element)] for component in ct.components]
    k0, k1 = keys.key_switch(ct.level, rotated[1], element)
    return Ciphertext(p, ct.level, [poly_add(rotated[0], k0, modulus), k1], ct.bound + p.key_switch_noise(ct.level))


def switch_down(ct: Ciphertext) -> Ciphertext:
    p = ct.profile
    dropped = p.main[ct.level]
    lower = p.modulus(ct.level - 1)
    inverse_t = pow(p.t, -1, dropped)
    components = []
    for component in ct.components:
        out = []
        for value in component:
            correction = p.t * centered(value * inverse_t, dropped)
            quotient, remainder = divmod(value - correction, dropped)
            assert remainder == 0
            out.append(quotient % lower)
        components.append(out)
    return Ciphertext(p, ct.level - 1, components, p.switch_down_noise(ct.bound, ct.level))


# ---------------------------------------------------------------------------
# Arbitrary-chain RNS vectors (stage one)
# ---------------------------------------------------------------------------


def lcg(state: int) -> int:
    return (state * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF


def chain_vectors() -> list[str]:
    """Centered conversion and congruence-preserving scale-down over many 50 to 60-bit primes."""
    lines = ["[rns_chain]"]
    step = 2 * 8 * 257
    main = first_primes(50, step, 18)
    special = first_primes(60, step, 6)
    targets = [257, 65537, 786433, special[0], (1 << 62) + 1]
    modulus = product(main)
    half = (modulus - 1) // 2
    state = 0x243F6A8885A308D3
    values = [0, 1, -1, half, -half, half - 1, -(half - 1), 128, -128]
    while len(values) < 24:
        wide = 0
        for _ in range(16):
            state = lcg(state)
            wide = (wide << 64) | state
        values.append(wide % modulus - half)
    lines.append("main = " + ",".join(str(prime) for prime in main))
    lines.append("special = " + ",".join(str(prime) for prime in special))
    lines.append("targets = " + ",".join(str(target) for target in targets))
    lines.append("values = " + ",".join(str(value) for value in values))
    lines.append("source_words = " + hex_words(words([value % modulus for value in values], main)))
    lines.append("centered_words = " + hex_words([value % target for target in targets for value in values]))
    lines.append(
        "canonical_words = " + hex_words([(value % modulus) % target for target in targets for value in values])
    )
    # Scale-down by the last prime (a modulus switch) and by the special basis (key switching).
    for name, kept, dropped in (("drop_last", main[:-1], main[-1:]), ("drop_special", main, special)):
        for scale in (257, 1):
            dropped_product = product(dropped)
            kept_product = product(kept)
            total = kept_product * dropped_product
            total_half = (total - 1) // 2
            inputs = [0, 1, -1, total_half, -total_half, dropped_product, -dropped_product, (dropped_product - 1) // 2]
            while len(inputs) < 20:
                wide = 0
                for _ in range(24):
                    state = lcg(state)
                    wide = (wide << 64) | state
                inputs.append(wide % total - total_half)
            inverse = pow(scale, -1, dropped_product)
            outputs = []
            for value in inputs:
                correction = scale * centered(value * inverse, dropped_product)
                quotient, remainder = divmod(value - correction, dropped_product)
                assert remainder == 0
                assert (quotient * dropped_product - value) % scale == 0
                assert 2 * abs(quotient * dropped_product - value) <= scale * dropped_product
                outputs.append(quotient)
            prefix = f"{name}_scale{scale}"
            lines.append(f"{prefix}_kept_in = " + hex_words(words([v % total for v in inputs], kept)))
            lines.append(f"{prefix}_dropped_in = " + hex_words(words([v % total for v in inputs], dropped)))
            lines.append(f"{prefix}_kept_out = " + hex_words(words([v % kept_product for v in outputs], kept)))
    return lines


# ---------------------------------------------------------------------------
# Known answers
# ---------------------------------------------------------------------------


def hex_words(values: list[int]) -> str:
    return "".join(format(value, "016x") for value in values)


def signed(values: list[int]) -> str:
    return ",".join(str(value) for value in values)


def master_seed(tag: int) -> bytes:
    return bytes((tag * 17 + index * 29 + 3) % 256 for index in range(64))


def scheme_vectors(name: str, profile: Profile, tag: int, element: int) -> list[str]:
    p = profile
    n = p.degree
    lines = [f"[{name}]"]

    def put(key: str, value) -> None:
        lines.append(f"{key} = {value}")

    put("log_degree", p.log_degree)
    put("plaintext_modulus", p.t)
    put("main_primes", signed(p.main))
    put("main_roots", signed(p.main_roots))
    put("special_primes", signed(p.special))
    put("special_roots", signed(p.special_roots))
    put("digit_primes", p.digit_primes)
    put("identity", p.identity().hex())
    put("master_seed", master_seed(tag).hex())
    put("seed0", fixture_seed(master_seed(tag), 0).hex())
    put("galois_element", element)
    keys = Keys(p, master_seed(tag), [element])
    full = p.main + p.special
    put("secret", signed(keys.secret))
    put("public_key", hex_words(words(keys.pk_b, p.main) + words(keys.pk_a, p.main)))
    for tag_name, key_tag in (("relinearization_key", 0), ("galois_key", element)):
        flat = []
        for b, a in keys.switching[key_tag]:
            flat += words(b, full) + words(a, full)
        put(tag_name, hex_words(flat))
    message1 = [(index * 37 + 250) % p.t for index in range(n)]
    message2 = [(index * index * 11 + 5) % p.t for index in range(n)]
    put("message1", signed(message1))
    put("message2", signed(message2))
    ct1 = keys.encrypt(message1)
    ct2 = keys.encrypt(message2)

    def record(label: str, ct: Ciphertext, expected: list[int]) -> None:
        put(f"{label}_level", ct.level)
        put(f"{label}_words", hex_words(ct.words()))
        put(f"{label}_bound", ct.bound)
        put(f"{label}_noise", keys.exact_noise(ct))
        decrypted = keys.decrypt(ct)
        assert decrypted == [value % p.t for value in expected], label
        assert keys.exact_noise(ct) <= ct.bound, label
        put(f"{label}_plain", signed(decrypted))

    record("ct1", ct1, message1)
    record("ct2", ct2, message2)
    record("sum", add(ct1, ct2), [a + b for a, b in zip(message1, message2)])
    record("difference", sub(ct1, ct2), [a - b for a, b in zip(message1, message2)])
    half = (p.t - 1) // 2
    record("plain_sum", add_plain(ct1, message2, half), [a + b for a, b in zip(message1, message2)])
    plain_product = poly_mul(message1, message2, p.t)
    record("plain_product", mul_plain(ct1, message2, half * n), plain_product)
    product_ct = tensor(ct1, ct2)
    record("tensor", product_ct, plain_product)
    relinearized = relinearize(keys, product_ct)
    record("relinearized", relinearized, plain_product)
    switched = switch_down(relinearized)
    record("switched", switched, plain_product)
    rotated = apply_galois(keys, switched, element)
    record("rotated", rotated, poly_automorphism(plain_product, element))
    lowest = rotated
    while lowest.level > 0:
        lowest = switch_down(lowest)
    record("lowest", lowest, poly_automorphism(plain_product, element))
    square = relinearize(keys, tensor(switched, switched))
    record("square", square, poly_mul(plain_product, plain_product, p.t))
    put("draws", keys.draws)
    return lines


def render() -> str:
    lines = [
        "# Known answers of the iroha_fhe RNS-BGV scheme.",
        "# Generated by crates/iroha_fhe/tests/vectors/bgv_reference.py; do not edit.",
        "# Words are 16 hexadecimal digits each, most significant digit first.",
    ]
    lines += chain_vectors()
    # A 30-bit toy chain with a partial last digit, and a chain of 50 and 60-bit primes.
    lines += scheme_vectors("toy16", Profile(4, 257, 30, 5, 31, 2, 2), 1, 5)
    lines += scheme_vectors("wide8", Profile(3, 257, 50, 6, 60, 2, 2), 2, 3)
    # A fully splitting plaintext modulus with single-prime digits.
    lines += scheme_vectors("split16", Profile(4, 97, 40, 4, 41, 2, 1), 3, 31)
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    text = render()
    if "--write" in argv:
        KAT_FILE.write_text(text)
        return 0
    if "--check" in argv:
        if not KAT_FILE.exists() or KAT_FILE.read_text() != text:
            print(f"{KAT_FILE} differs from the reference output", file=sys.stderr)
            return 1
        return 0
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
