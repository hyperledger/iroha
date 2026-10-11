"""Independent transcript equations from PIPA §6 and retained constants."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from . import require
from .curve import Curve, P

KATS = json.loads((Path(__file__).resolve().parents[1] / 'kats_v1.json').read_text())


class Sponge:
    """Plain width-three RP57 permutation, with the specified rate-two padding."""

    def __init__(self, modulus: int):
        key = 'fp' if modulus == P else 'fq'
        constants = KATS['poseidon_constants']
        self.modulus = modulus
        self.constants = [[int.from_bytes(bytes.fromhex(x), 'little') for x in row]
                          for row in constants[key]['round_constants']]
        self.mds = [[int.from_bytes(bytes.fromhex(x), 'little') for x in row]
                    for row in constants[key]['mds']]
        require(constants['full_rounds'] == 8 and constants['partial_rounds'] == 57,
                'RP57 constant profile')
        self.state = [1 << 64, 0, 0]
        self.buffer = []

    def absorb(self, value: int):
        """Append a native canonical field element to the current duplex buffer."""
        require(type(value) is int and 0 <= value < self.modulus, 'sponge element')
        self.buffer.append(value)

    def permute(self):
        """The unoptimized constant/MDS definition, independent of Rust kernels."""
        m = self.modulus
        state = self.state
        for i, constants in enumerate(self.constants):
            state = [(x + c) % m for x, c in zip(state, constants)]
            if i < 4 or i >= 61:
                state = [pow(x, 5, m) for x in state]
            else:
                state[0] = pow(state[0], 5, m)
            state = [sum(a*b for a, b in zip(row, state)) % m for row in self.mds]
        self.state = state

    def squeeze(self):
        """Apply an explicit 1 padding element, including the even-length case."""
        pending = self.buffer + [1]
        self.buffer = []
        for start in range(0, len(pending), 2):
            for offset, value in enumerate(pending[start:start + 2]):
                self.state[1 + offset] = (self.state[1 + offset] + value) % self.modulus
            self.permute()
        return self.state[1]


class Transcript:
    """One explicit transcript profile, canonical proof reader and challenge tape."""

    def __init__(self, curve: Curve, profile: int, proof: bytes, *, oracle: bool = False):
        require(type(profile) is int and profile in (0, 1, 2), 'transcript profile')
        require(isinstance(proof, bytes), 'encoded proof required')
        require(not oracle or profile != 2, 'no base-field oracle fallback')
        self.curve, self.profile, self.proof, self.oracle = curve, profile, proof, oracle
        self.position = 0
        self.challenges = []
        if profile == 0:
            self.hash = hashlib.blake2b(digest_size=64, person=b'Halo2-Transcript')
        else:
            self.sponge = Sponge(curve.scalar if profile == 1 else curve.base)
            if profile == 2:
                self.sponge.absorb(int.from_bytes(b'pipa-rb1', 'little'))

    def common_scalar(self, value: int):
        """Absorb a proof scalar without ever accepting a noncanonical value."""
        require(type(value) is int and 0 <= value < self.curve.scalar, 'transcript scalar')
        if self.profile == 0:
            self.hash.update(b'\x02' + value.to_bytes(32, 'little'))
        elif self.profile == 1 or self.curve.tag == 1:
            self.sponge.absorb(value)
        else:
            self.sponge.absorb(value & ((1 << 128) - 1))
            self.sponge.absorb(value >> 128)

    def common_native(self, value: int):
        """Metadata is native to the base field only in the explicit PIPA-R profile."""
        if self.profile == 2:
            self.sponge.absorb(value)
        else:
            self.common_scalar(value)

    def common_point(self, point):
        """Use the selected profile's exact canonical nonidentity point encoding."""
        require(point[2] != 0, 'identity transcript point')
        x, y = self.curve.affine(point)
        if self.profile == 0:
            self.hash.update(b'\x01' + x.to_bytes(32, 'little') + y.to_bytes(32, 'little'))
        elif self.profile == 2:
            self.sponge.absorb(x)
            self.sponge.absorb(y)
        elif self.oracle:
            self.sponge.absorb(x % self.curve.scalar)
            self.sponge.absorb(y % self.curve.scalar)
        else:
            self.sponge.absorb(x % self.curve.scalar)
            self.sponge.absorb(int(x >= self.curve.scalar) + 2 * (y & 1))

    def squeeze(self):
        """Return and record one scalar challenge from the profile's hash state."""
        if self.profile == 0:
            self.hash.update(b'\0')
            value = int.from_bytes(self.hash.digest(), 'little') % self.curve.scalar
        else:
            value = self.sponge.squeeze() % self.curve.scalar
        self.challenges.append(value)
        return value

    def message(self):
        """Consume exactly one fixed-width proof message."""
        require(self.position + 32 <= len(self.proof), 'truncated proof')
        raw = self.proof[self.position:self.position + 32]
        self.position += 32
        return raw

    def point(self, *, absorb: bool = True):
        """Decode one canonical nonidentity point and optionally absorb it."""
        point = self.curve.decode(self.message())
        if absorb:
            self.common_point(point)
        return point

    def scalar(self):
        """Decode and absorb one canonical scalar."""
        scalar = self.curve.scalar_bytes(self.message())
        self.common_scalar(scalar)
        return scalar

    def finish(self):
        """Reject any proof suffix beyond the descriptor-selected messages."""
        require(self.position == len(self.proof), 'trailing proof')
