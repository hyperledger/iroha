#!/usr/bin/env python3
"""Standard-library PIPA-R transcript KAT calculation, independent of Rust arithmetic.

Reads the pinned canonical RP57 parameter tables. This is a transcript reference,
not the full independent-author PLONK/AS verifier required by G4.1.
"""
from pathlib import Path

P = int("40000000000000000000000000000000224698fc094cf91b992d30ed00000001", 16)
Q = int("40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001", 16)


class Sponge:
    def __init__(self, modulus, table):
        raw = Path(table).read_bytes()
        assert len(raw) == (65 * 3 + 9) * 32
        words = [int.from_bytes(raw[i:i + 32], "little") for i in range(0, len(raw), 32)]
        assert all(x < modulus for x in words)
        self.p, self.rc, self.mds = modulus, words[:195], words[195:]
        self.state, self.buffer = [1 << 64, 0, 0], []

    def absorb(self, *values):
        assert all(0 <= v < self.p for v in values)
        self.buffer.extend(values)

    def squeeze(self):
        values = self.buffer + [1]
        self.buffer = []
        if len(values) % 2:
            values.append(0)
        for offset in range(0, len(values), 2):
            self.state[1] = (self.state[1] + values[offset]) % self.p
            self.state[2] = (self.state[2] + values[offset + 1]) % self.p
            for round_ in range(65):
                s = [(x + c) % self.p for x, c in zip(self.state, self.rc[3 * round_:3 * round_ + 3])]
                for j in range(3 if round_ < 4 or round_ >= 61 else 1):
                    s[j] = pow(s[j], 5, self.p)
                self.state = [sum(self.mds[3 * i + j] * s[j] for j in range(3)) % self.p for i in range(3)]
        return self.state[1]


def vector(base, scalar, table):
    sponge = Sponge(base, table)
    sponge.absorb(int.from_bytes(b"pipa-rb1", "little"), 5,
                  int.from_bytes(b"pipainst", "little"), 1, 2, 1)
    def absorb_scalar(value):
        sponge.absorb(value) if scalar < base else sponge.absorb(value % (1 << 128), value >> 128)
    absorb_scalar(3)
    absorb_scalar(scalar - 1)
    sponge.absorb(base - 1, 2)  # the canonical finite point (-1, 2)
    first = sponge.squeeze() % scalar
    second = sponge.squeeze() % scalar
    absorb_scalar(first)
    absorb_scalar(0)
    third = sponge.squeeze() % scalar
    return [x.to_bytes(32, "little").hex() for x in [first, second, third]]


if __name__ == "__main__":
    tables = Path(__file__).resolve().parents[2] / "iroha_pasta" / "src" / "poseidon"
    for name, b, f in [("pallas", P, Q), ("vesta", Q, P)]:
        path = tables / ("rp57_fp.bin" if b == P else "rp57_fq.bin")
        print(name, *vector(b, f, path), sep="\n")
