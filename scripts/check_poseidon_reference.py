#!/usr/bin/env python3
"""Independently rederive the fixed RP56 test corpus using integer arithmetic.

This verifier does not read native constants or call a Rust implementation.
The fixtures were captured from poseidon-primitives 0.2.0 before retirement.
Grain uses a single-bit shift register, followed by rejection sampling and
Cauchy matrix inversion; the native implementation uses batched bit updates.
"""

from pathlib import Path

BN254 = int("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001", 16)
FP = int("40000000000000000000000000000000224698fc094cf91b992d30ed00000001", 16)


def parameters(modulus, width):
    """Derive all 64 round rows and the secure_mds=0 Cauchy matrix."""
    bits = modulus.bit_length()
    seed = ((1, 2), (0, 4), (bits, 12), (width, 12), (8, 10), (56, 10))
    state = [int(bit) for value, size in seed for bit in f"{value:0{size}b}"] + [1] * 30
    assert len(state) == 80

    def shift():
        bit = state[0] ^ state[13] ^ state[23] ^ state[38] ^ state[51] ^ state[62]
        state.pop(0)
        state.append(bit)
        return bit

    for _ in range(160):
        shift()

    def word():
        value = 0
        for _ in range(bits):
            while True:
                select, bit = shift(), shift()
                if select:
                    value = (value << 1) | bit
                    break
        return value

    constants = []
    while len(constants) < 64 * width:
        value = word()
        if value < modulus:
            constants.append(value)
    while True:
        points = [word() % modulus for _ in range(2 * width)]
        if len(set(points)) == len(points):
            break
    xs, ys = points[:width], points[width:]
    mds = [[pow((x + y) % modulus, -1, modulus) for y in ys] for x in xs]
    return [constants[i:i + width] for i in range(0, len(constants), width)], mds


def permutation(state, modulus, rounds, mds):
    """Evaluate the complete dense permutation over Python integers."""
    for index, row in enumerate(rounds):
        state = [(x + c) % modulus for x, c in zip(state, row, strict=True)]
        if 4 <= index < 60:
            state[0] = pow(state[0], 5, modulus)
        else:
            state = [pow(x, 5, modulus) for x in state]
        state = [sum(c * x for c, x in zip(row, state, strict=True)) % modulus for row in mds]
    return state


def expected_corpus():
    """Return exact little-endian hex text for every pinned reference file."""
    result = {}
    for name, modulus, width in [
        ("bn254-w3-rp56", BN254, 3), ("bn254-w6-rp56", BN254, 6),
        ("pasta-fp-w3-rp56", FP, 3),
    ]:
        rounds, mds = parameters(modulus, width)
        result[name + ".hex"] = "".join(x.to_bytes(32, "little").hex() + "\n" for row in rounds + mds for x in row)
    rounds, mds = parameters(FP, 3)
    vectors = []
    for domain in [0x4B41494749563143, 0x4B4149474956314E, 0x4B41494749563141]:
        for length in range(34):
            frame = [length] + [pow(2, 190, FP) + 987654321 + i for i in range(length)] + [1]
            if len(frame) % 2:
                frame.append(0)
            state = [0, 0, domain]
            for offset in range(0, len(frame), 2):
                state[0] += frame[offset]
                state[1] += frame[offset + 1]
                state = permutation(state, FP, rounds, mds)
            vectors.append(f"{domain:x} {length} {state[0].to_bytes(32, 'little').hex()}\n")
    result["kaigi-framed-rp56.hex"] = "".join(vectors)
    return result


def verify_directory(directory):
    """Reject missing, altered, reordered or noncanonical reference bytes."""
    for name, expected in expected_corpus().items():
        actual = (directory / name).read_bytes()
        if actual != expected.encode("ascii"):
            raise ValueError(f"Poseidon reference mismatch: {name}")


def main():
    """Verify the checked-in corpus, without any write or regeneration mode."""
    root = Path(__file__).resolve().parents[1]
    verify_directory(root / "fixtures/poseidon")
    print("PASS: 822 parameter fields and 102 complete framed-sponge vectors")


if __name__ == "__main__":
    main()
