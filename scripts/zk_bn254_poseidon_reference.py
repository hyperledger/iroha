#!/usr/bin/env python3
"""Independent regeneration of the BN254 Poseidon parameters used by the repository.

Requires Python 3.9+ and its standard library only. Nothing is downloaded and no
environment variable is read. This is the reference half of task H.1 of
specs/zk_delivery_plan.md; scripts/check_zk_primitive_workloads.py imports it.

What it does
* Regenerates round constants and the dense MDS matrix with the Grain LFSR in
  self-shrinking mode and the Cauchy construction `1 / (x_i + y_j)` described in
  the Poseidon paper (Grassi, Khovratovich, Rechberger, Roy, Schofnegger, USENIX
  Security 2021, eprint 2019/458) and its `generate_parameters_grain.sage`
  script. The implementation here shares no code with the Rust owner or with the
  `poseidon-primitives` test oracle.
* Compares the result with the 621 fixed field elements in
  crates/iroha_zkp_poseidon/src/poseidon/bn254_v1.rs.
* Compares the same generator, run with the published round numbers, with pinned
  values of the published BN254 width-three instantiation
  (`poseidonperm_x5_254_3`), so the generator itself is anchored to published
  constants rather than only to the repository table.
* Checks every square minor of both matrices and three bounded linear-layer
  screens for one active S-box per partial round.
* Evaluates the paper's round-number inequalities for `x^5` at a 128-bit target
  with the +2 full round and +7.5% partial round margin.
* Computes deterministic permutation and helper vectors that the Rust test
  `bn254_v1_reference_vectors_tests` pins.

What it does not establish
* Parameter equality, MDS minors and the bounded screens are not a security
  proof. The round-number inequalities are transcribed from the paper; the
  original script was not fetched. A value below the margin rule is recorded as
  a margin-rule defect candidate, not as an attack.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import math
from pathlib import Path
import re
import sys
from typing import Iterator, Sequence

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_TABLE = "crates/iroha_zkp_poseidon/src/poseidon/bn254_v1.rs"
VECTOR_FIXTURE = "crates/iroha_zkp_poseidon/src/poseidon/bn254_v1_reference_vectors.txt"

# BN254 (alt_bn128) scalar field modulus.
BN254_FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617
FIELD_BITS = 254
ALPHA = 5
SECURITY_BITS = 128
FULL_ROUNDS = 8
REPOSITORY_PARTIAL_ROUNDS = 56
WIDTHS = (3, 6)

# Published BN254 x^5 width-three instantiation: hadeshash
# `code/poseidonperm_x5_254_3.sage` (R_F = 8, R_P = 57). The first six round
# constants and the full MDS matrix are pinned here so the generator is checked
# against published values without any download. The same values ship in the
# `poseidon-primitives` 0.2.0 crate (`src/poseidon/primitives/bn256/fp.rs`) that
# the Rust owner uses as a test oracle.
PUBLISHED_WIDTH3_PARTIAL_ROUNDS = 57
PUBLISHED_WIDTH3_FIRST_ROUND_CONSTANTS = (
    6745197990210204598374042828761989596302876299545964402857411729872131034734,
    426281677759936592021316809065178817848084678679510574715894138690250139748,
    4014188762916583598888942667424965430287497824629657219807941460227372577781,
    21328925083209914769191926116470334003273872494252651254811226518870906634704,
    19525217621804205041825319248827370085205895195618474548469181956339322154226,
    1402547928439424661186498190603111095981986484908825517071607587179649375482,
)
PUBLISHED_WIDTH3_MDS = (
    (
        7511745149465107256748700652201246547602992235352608707588321460060273774987,
        10370080108974718697676803824769673834027675643658433702224577712625900127200,
        19705173408229649878903981084052839426532978878058043055305024233888854471533,
    ),
    (
        18732019378264290557468133440468564866454307626475683536618613112504878618481,
        20870176810702568768751421378473869562658540583882454726129544628203806653987,
        7266061498423634438633389053804536045105766754026813321943009179476902321146,
    ),
    (
        9131299761947733513298312097611845208338517739621853568979632113419485819303,
        10595341252162738537912664445405114076324478519622938027420701542910180337937,
        11597556804922396090267472882856054602429588299176362916247939723151043581408,
    ),
)

# SHA-256 of each repository table: round-major constants followed by the
# row-major MDS matrix, every element as 32 canonical little-endian bytes. The
# Rust test `bn254_parameter_exports_match_captured_bytes` pins the same values.
REPOSITORY_TABLE_SHA256 = {
    3: "20a6364b21446c75eafb313c00cda37f1e772a3e76f158d6938b40fd52988709",
    6: "443ee9a4a9e5f8425720a184e8ef3fbe1897c9fcae80e4c1827cf0a246889bda",
}

# The seed of the pseudo-random vector states. Fixed, so vectors are stable.
VECTOR_SEED = b"iroha:h1:bn254-poseidon:reference-vectors:v1"


# ---------------------------------------------------------------------------
# Grain LFSR and parameter generation
# ---------------------------------------------------------------------------


def grain_bits(width: int, full_rounds: int, partial_rounds: int) -> Iterator[int]:
    """Yield the self-shrinking Grain LFSR output for a prime-field `x^alpha` instance."""

    def field(value: int, bits: int) -> list[int]:
        return [(value >> (bits - 1 - index)) & 1 for index in range(bits)]

    # 2 bits field type (1 = prime), 4 bits S-box (0 = x^alpha), 12 bits field
    # size, 12 bits width, 10 bits R_F, 10 bits R_P, then 30 ones: 80 bits.
    state = (
        field(1, 2)
        + field(0, 4)
        + field(FIELD_BITS, 12)
        + field(width, 12)
        + field(full_rounds, 10)
        + field(partial_rounds, 10)
        + [1] * 30
    )
    assert len(state) == 80

    def step() -> int:
        bit = state[62] ^ state[51] ^ state[38] ^ state[23] ^ state[13] ^ state[0]
        state.pop(0)
        state.append(bit)
        return bit

    for _ in range(160):
        step()
    while True:
        # Self-shrinking: a first bit of one keeps the second bit of the pair.
        if step():
            yield step()
        else:
            step()


def _take(bits: Iterator[int], count: int) -> int:
    value = 0
    for _ in range(count):
        value = (value << 1) | next(bits)
    return value


def generate_parameters(
    width: int, full_rounds: int, partial_rounds: int
) -> tuple[list[list[int]], list[list[int]]]:
    """Return (round constants, MDS) for the first Cauchy candidate (`secure_mds = 0`)."""
    bits = grain_bits(width, full_rounds, partial_rounds)
    rounds = full_rounds + partial_rounds
    constants: list[list[int]] = []
    for _ in range(rounds):
        row = []
        while len(row) < width:
            candidate = _take(bits, FIELD_BITS)
            if candidate < BN254_FR:  # rejection sampling
                row.append(candidate)
        constants.append(row)
    while True:
        # The reference script reduces these values instead of rejecting them.
        values = [_take(bits, FIELD_BITS) % BN254_FR for _ in range(2 * width)]
        if len(set(values)) == len(values):
            break
    xs, ys = values[:width], values[width:]
    mds = []
    for x in xs:
        row = []
        for y in ys:
            total = (x + y) % BN254_FR
            if total == 0:
                raise ValueError("first Cauchy candidate has a zero denominator")
            row.append(pow(total, -1, BN254_FR))
        mds.append(row)
    return constants, mds


def table_sha256(constants: Sequence[Sequence[int]], mds: Sequence[Sequence[int]]) -> str:
    """SHA-256 of round-major constants then row-major MDS, little-endian 32 bytes each."""
    digest = hashlib.sha256()
    for row in itertools.chain(constants, mds):
        for value in row:
            digest.update(value.to_bytes(32, "little"))
    return digest.hexdigest()


def parse_repository_table(root: Path = ROOT) -> dict[int, tuple[list[list[int]], list[list[int]]]]:
    """Read the fixed tables from the Rust owner as integers."""
    text = (root / REPOSITORY_TABLE).read_text(encoding="utf-8")
    tables: dict[int, tuple[list[list[int]], list[list[int]]]] = {}
    for width in WIDTHS:
        match = re.search(
            rf"const WIDTH{width}: Bn254PoseidonParams<{width}> = Bn254PoseidonParams \{{(.*?)\n\}};",
            text,
            re.S,
        )
        if not match:
            raise ValueError(f"WIDTH{width} table not found in {REPOSITORY_TABLE}")
        body = match.group(1)
        split = body.index("mds:")
        parts = []
        for chunk in (body[:split], body[split:]):
            raw = bytes(int(token, 16) for token in re.findall(r"0x([0-9a-fA-F]{2})\b", chunk))
            if len(raw) % 32:
                raise ValueError(f"WIDTH{width} table is not a whole number of field elements")
            parts.append([int.from_bytes(raw[i : i + 32], "little") for i in range(0, len(raw), 32)])
        flat_constants, flat_mds = parts
        rounds = FULL_ROUNDS + REPOSITORY_PARTIAL_ROUNDS
        if len(flat_constants) != rounds * width or len(flat_mds) != width * width:
            raise ValueError(
                f"WIDTH{width} table has {len(flat_constants)} constants and {len(flat_mds)} "
                f"matrix entries; expected {rounds * width} and {width * width}"
            )
        constants = [flat_constants[i : i + width] for i in range(0, len(flat_constants), width)]
        mds = [flat_mds[i : i + width] for i in range(0, len(flat_mds), width)]
        tables[width] = (constants, mds)
    return tables


# ---------------------------------------------------------------------------
# Linear algebra over the prime field
# ---------------------------------------------------------------------------


def _row_reduce(rows: Sequence[Sequence[int]]) -> list[list[int]]:
    """Reduced row echelon basis of the row space."""
    matrix = [[value % BN254_FR for value in row] for row in rows]
    if not matrix:
        return []
    rank = 0
    for column in range(len(matrix[0])):
        pivot = next((i for i in range(rank, len(matrix)) if matrix[i][column]), None)
        if pivot is None:
            continue
        matrix[rank], matrix[pivot] = matrix[pivot], matrix[rank]
        inverse = pow(matrix[rank][column], -1, BN254_FR)
        matrix[rank] = [value * inverse % BN254_FR for value in matrix[rank]]
        for i, row in enumerate(matrix):
            if i != rank and row[column]:
                factor = row[column]
                matrix[i] = [(a - factor * b) % BN254_FR for a, b in zip(row, matrix[rank])]
        rank += 1
        if rank == len(matrix):
            break
    return matrix[:rank]


def _kernel(rows: Sequence[Sequence[int]], dimension: int) -> list[list[int]]:
    """Basis of `{v : row . v = 0 for every row}`."""
    reduced = _row_reduce(rows)
    pivots = [next(j for j, value in enumerate(row) if value) for row in reduced]
    basis = []
    for free in range(dimension):
        if free in pivots:
            continue
        vector = [0] * dimension
        vector[free] = 1
        for row, pivot in zip(reduced, pivots):
            vector[pivot] = -row[free] % BN254_FR
        basis.append(vector)
    return _row_reduce(basis)


def _matmul(a: Sequence[Sequence[int]], b: Sequence[Sequence[int]]) -> list[list[int]]:
    return [
        [sum(x * y for x, y in zip(row, column)) % BN254_FR for column in zip(*b)] for row in a
    ]


def _apply(matrix: Sequence[Sequence[int]], vector: Sequence[int]) -> list[int]:
    return [sum(x * y for x, y in zip(row, vector)) % BN254_FR for row in matrix]


def determinant(matrix: Sequence[Sequence[int]]) -> int:
    """Determinant modulo the field by elimination."""
    work = [[value % BN254_FR for value in row] for row in matrix]
    size = len(work)
    result = 1
    for column in range(size):
        pivot = next((i for i in range(column, size) if work[i][column]), None)
        if pivot is None:
            return 0
        if pivot != column:
            work[column], work[pivot] = work[pivot], work[column]
            result = -result % BN254_FR
        result = result * work[column][column] % BN254_FR
        inverse = pow(work[column][column], -1, BN254_FR)
        for i in range(column + 1, size):
            factor = work[i][column] * inverse % BN254_FR
            if factor:
                work[i] = [(a - factor * b) % BN254_FR for a, b in zip(work[i], work[column])]
    return result


def square_minor_report(mds: Sequence[Sequence[int]]) -> dict[str, int]:
    """Count the square minors of the matrix and those that vanish."""
    width = len(mds)
    total = 0
    zero = 0
    for size in range(1, width + 1):
        for rows in itertools.combinations(range(width), size):
            for columns in itertools.combinations(range(width), size):
                total += 1
                if determinant([[mds[i][j] for j in columns] for i in rows]) == 0:
                    zero += 1
    return {"square_minors": total, "zero_minors": zero}


def linear_layer_screens(mds: Sequence[Sequence[int]]) -> dict[str, object]:
    """Bounded screens for one active S-box (coordinate 0) per partial round.

    * `inactive_invariant_dimension`: dimension of the largest subspace of
      `{x : x_0 = 0}` that the matrix maps into itself, computed by the descending
      intersection `S <- S ∩ M^-1 S`. Zero means no infinitely long invariant
      subspace trail avoids the S-box (the decision of GRS21 Algorithm 1).
    * `krylov_ranks`: for each power `M^r`, `1 <= r <= 4 * width`, the dimension of
      `span(e_0, M^r e_0, M^2r e_0, ...)`. Full rank for every power is the
      conservative form of the active and iterative screens (GRS21 Algorithms 2
      and 3) that scripts/fastpq/check_compact_mds.py applies to its matrix.
    """
    width = len(mds)
    current = _row_reduce(
        [[int(i == j) for j in range(width)] for i in range(1, width)]
    )
    while current:
        orthogonal = _kernel(current, width)
        following = _kernel(orthogonal + _matmul(orthogonal, mds), width)
        if following == current:
            break
        current = following
    power = [[int(i == j) for j in range(width)] for i in range(width)]
    ranks = []
    for _ in range(4 * width):
        power = _matmul(power, mds)
        vector = [1] + [0] * (width - 1)
        vectors = []
        for _ in range(width):
            vectors.append(vector)
            vector = _apply(power, vector)
        ranks.append(len(_row_reduce(vectors)))
    return {
        "inactive_invariant_dimension": len(current),
        "krylov_powers_checked": 4 * width,
        "krylov_ranks_all_full": all(rank == width for rank in ranks),
    }


# ---------------------------------------------------------------------------
# Round numbers
# ---------------------------------------------------------------------------


def round_number_bounds(width: int, full_rounds: int, partial_rounds: int) -> dict[str, object]:
    """Evaluate the paper's `x^alpha` inequalities for unmargined round numbers.

    The five lower bounds on the number of full rounds follow section 5.5 of
    the Poseidon paper for a prime field: the statistical bound, the
    interpolation bound and three Groebner-basis bounds. `min(M, n)` uses the
    field size in bits.
    """
    log_alpha_2 = math.log(2, ALPHA)
    statistical = 6 if SECURITY_BITS <= (FIELD_BITS - (ALPHA - 1) / 2) * (width + 1) else 10
    interpolation = (
        1
        + math.ceil(log_alpha_2 * min(SECURITY_BITS, FIELD_BITS))
        + math.ceil(math.log(width, ALPHA) - 1e-12)
        - partial_rounds
    )
    groebner_1 = log_alpha_2 * min(SECURITY_BITS, FIELD_BITS) - partial_rounds
    groebner_2 = (
        width
        - 1
        + log_alpha_2 * min(SECURITY_BITS / (width + 1), FIELD_BITS / 2)
        - partial_rounds
    )
    groebner_3 = (
        width - 2 + SECURITY_BITS / (2 * math.log(ALPHA, 2)) - partial_rounds
    ) / (width - 1)
    required = max(
        statistical,
        interpolation,
        math.ceil(groebner_1),
        math.ceil(groebner_2),
        math.ceil(groebner_3),
    )
    return {
        "statistical": statistical,
        "interpolation": interpolation,
        "required_full_rounds": required,
        "satisfied": full_rounds >= required,
    }


def recommended_round_numbers(width: int) -> dict[str, int]:
    """Smallest S-box count that satisfies the inequalities, then the paper's margin.

    The objective is the number of S-boxes `width * R_F + R_P`; ties prefer fewer
    full rounds. The margin adds two full rounds and 7.5% partial rounds,
    rounded up.
    """
    best: tuple[int, int, int] | None = None
    unmargined: tuple[int, int] | None = None
    for partial in range(1, 200):
        for full in range(4, 40, 2):
            if not round_number_bounds(width, full, partial)["satisfied"]:
                continue
            margin_full = full + 2
            margin_partial = math.ceil(partial * 1.075)
            cost = width * margin_full + margin_partial
            candidate = (cost, margin_full, margin_partial)
            if best is None or candidate < best:
                best = candidate
                unmargined = (full, partial)
    assert best is not None and unmargined is not None
    return {
        "full_rounds": best[1],
        "partial_rounds": best[2],
        "unmargined_full_rounds": unmargined[0],
        "unmargined_partial_rounds": unmargined[1],
    }


def minimum_partial_rounds(width: int, full_rounds: int) -> dict[str, int]:
    """Smallest R_P for the given margined R_F, without and with the 7.5% margin."""
    unmargined_full = full_rounds - 2
    for partial in range(1, 400):
        if round_number_bounds(width, unmargined_full, partial)["satisfied"]:
            return {
                "without_margin": partial,
                "with_margin": math.ceil(partial * 1.075),
            }
    raise ValueError("no partial round count satisfies the inequalities")


# ---------------------------------------------------------------------------
# Permutation and repository helper semantics
# ---------------------------------------------------------------------------


def permute(
    state: Sequence[int], constants: Sequence[Sequence[int]], mds: Sequence[Sequence[int]]
) -> list[int]:
    """Original Poseidon: R_F/2 full, R_P partial (S-box on coordinate 0), R_F/2 full."""
    width = len(state)
    half = FULL_ROUNDS // 2
    partial_end = len(constants) - half
    current = [value % BN254_FR for value in state]
    for index, row in enumerate(constants):
        current = [(value + constant) % BN254_FR for value, constant in zip(current, row)]
        if index < half or index >= partial_end:
            current = [pow(value, ALPHA, BN254_FR) for value in current]
        else:
            current[0] = pow(current[0], ALPHA, BN254_FR)
        current = _apply(mds, current)
    assert len(current) == width
    return current


def hash2(a: int, b: int, table3) -> int:
    """`hash2_bytes`: state `[a, b, 0]`, one permutation, coordinate 0."""
    return permute([a, b, 0], *table3)[0]


def hash6(inputs: Sequence[int], table6) -> int:
    """`hash6_bytes`: all six state coordinates are inputs, one permutation, coordinate 0."""
    return permute(list(inputs), *table6)[0]


def hash_bytes(data: bytes, table3) -> int:
    """`hash_bytes`: little-endian u64 words, byte delimiter 0x01, field padding 1, rate 2."""
    words = [int.from_bytes(data[i : i + 8], "little") for i in range(0, len(data) - len(data) % 8, 8)]
    tail = data[len(data) - len(data) % 8 :]
    words.append(int.from_bytes(tail, "little") | (1 << (8 * len(tail))))
    state = [0, 0, 0]
    index = 0
    while index + 1 < len(words):
        state[0] = (state[0] + words[index]) % BN254_FR
        state[1] = (state[1] + words[index + 1]) % BN254_FR
        state = permute(state, *table3)
        index += 2
    if index == len(words):
        state[0] = (state[0] + 1) % BN254_FR
    else:
        state[0] = (state[0] + words[index]) % BN254_FR
        state[1] = (state[1] + 1) % BN254_FR
    return permute(state, *table3)[0]


def _seeded_state(label: str, width: int) -> list[int]:
    stream = hashlib.shake_256(VECTOR_SEED + b"|" + label.encode("ascii")).digest(64 * width)
    return [int.from_bytes(stream[64 * i : 64 * i + 64], "little") % BN254_FR for i in range(width)]


def _hex(value: int) -> str:
    return value.to_bytes(32, "little").hex()


def reference_vectors(tables) -> dict[str, object]:
    """Deterministic vectors over the repository parameters (little-endian hex)."""
    table3, table6 = tables[3], tables[6]
    permutation3 = []
    states3 = {
        "zero": [0, 0, 0],
        "sequential": [0, 1, 2],
        "all_p_minus_one": [BN254_FR - 1] * 3,
        "unit_0": [1, 0, 0],
        "unit_1": [0, 1, 0],
        "unit_2": [0, 0, 1],
        "seeded_0": _seeded_state("width3:0", 3),
        "seeded_1": _seeded_state("width3:1", 3),
    }
    for name, state in states3.items():
        permutation3.append(
            {
                "name": name,
                "input": [_hex(value) for value in state],
                "output": [_hex(value) for value in permute(state, *table3)],
            }
        )
    max64 = (1 << 64) - 1
    hash2_cases = [(0, 0), (1, 2), (max64, max64), (0x0123456789ABCDEF, 0xFEDCBA9876543210)]
    hash6_cases = [
        [0] * 6,
        [1, 2, 3, 4, 5, 6],
        [max64] * 6,
        [1, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 1],
        [value & max64 for value in _seeded_state("hash6:0", 6)],
    ]
    byte_cases = [
        b"",
        b"poseidon",
        bytes(range(9)),
        bytes(range(16)),
        b"iroha:h1:domain-a",
        b"iroha:h1:domain-b",
        b"\x01",
        b"\x01\x00",
    ]
    return {
        "permutation_width3": permutation3,
        "hash2": [
            {"a": a, "b": b, "output": _hex(hash2(a, b, table3))} for a, b in hash2_cases
        ],
        "hash6": [
            {"inputs": inputs, "output": _hex(hash6(inputs, table6))} for inputs in hash6_cases
        ],
        "hash_bytes": [
            {"input": data.hex(), "output": _hex(hash_bytes(data, table3))} for data in byte_cases
        ],
        "non_canonical_field_encodings": [
            _hex_wide(BN254_FR),
            _hex_wide(BN254_FR + 1),
            "ff" * 32,
        ],
        # First round constant of the published width-three instantiation
        # (R_P = 57). The repository table (R_P = 56) must not contain it.
        "published_width3_first_round_constant": _hex(PUBLISHED_WIDTH3_FIRST_ROUND_CONSTANTS[0]),
    }


def _hex_wide(value: int) -> str:
    return value.to_bytes(32, "little").hex()


def render_vector_fixture(vectors: dict[str, object]) -> str:
    """Render the vectors as the line-oriented fixture the Rust test reads."""
    lines = [
        "# BN254 Poseidon reference vectors (repository parameters: x^5, R_F = 8, R_P = 56).",
        "# Generated by `python3 scripts/zk_bn254_poseidon_reference.py --write-vectors`.",
        "# Field elements are 32-byte canonical little-endian hex. Do not edit by hand.",
    ]
    for entry in vectors["permutation_width3"]:
        lines.append(" ".join(["permute3", entry["name"], *entry["input"], *entry["output"]]))
    for entry in vectors["hash2"]:
        lines.append(f"hash2 {entry['a']} {entry['b']} {entry['output']}")
    for entry in vectors["hash6"]:
        lines.append(" ".join(["hash6", *(str(value) for value in entry["inputs"]), entry["output"]]))
    for entry in vectors["hash_bytes"]:
        lines.append(f"hash_bytes {entry['input'] or '-'} {entry['output']}")
    for encoding in vectors["non_canonical_field_encodings"]:
        lines.append(f"non_canonical {encoding}")
    lines.append(f"published_width3_first_round_constant {vectors['published_width3_first_round_constant']}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


def build_report(root: Path = ROOT) -> dict[str, object]:
    """Regenerate, compare and analyse; raise `ValueError` on any mismatch."""
    tables = parse_repository_table(root)
    widths: dict[str, object] = {}
    for width in WIDTHS:
        generated = generate_parameters(width, FULL_ROUNDS, REPOSITORY_PARTIAL_ROUNDS)
        if generated != tables[width]:
            raise ValueError(
                f"width {width}: the repository table differs from the Grain/Cauchy regeneration"
            )
        digest = table_sha256(*generated)
        if digest != REPOSITORY_TABLE_SHA256[width]:
            raise ValueError(f"width {width}: table digest {digest} differs from the pinned value")
        minors = square_minor_report(generated[1])
        if minors["zero_minors"]:
            raise ValueError(f"width {width}: the matrix has a vanishing square minor")
        screens = linear_layer_screens(generated[1])
        if screens["inactive_invariant_dimension"] or not screens["krylov_ranks_all_full"]:
            raise ValueError(f"width {width}: a bounded linear-layer screen failed")
        recommended = recommended_round_numbers(width)
        minimum = minimum_partial_rounds(width, FULL_ROUNDS)
        widths[str(width)] = {
            "rate": width - 1,
            "field_elements": (FULL_ROUNDS + REPOSITORY_PARTIAL_ROUNDS) * width + width * width,
            "table_sha256": digest,
            **minors,
            **screens,
            "repository_full_rounds": FULL_ROUNDS,
            "repository_partial_rounds": REPOSITORY_PARTIAL_ROUNDS,
            "margin_rule_full_rounds": recommended["full_rounds"],
            "margin_rule_partial_rounds": recommended["partial_rounds"],
            "minimum_partial_rounds_without_margin": minimum["without_margin"],
            "minimum_partial_rounds_with_margin": minimum["with_margin"],
            "repository_meets_margin_rule": REPOSITORY_PARTIAL_ROUNDS >= minimum["with_margin"],
            "repository_meets_unmargined_bound": REPOSITORY_PARTIAL_ROUNDS
            >= minimum["without_margin"] and round_number_bounds(
                width, FULL_ROUNDS - 2, REPOSITORY_PARTIAL_ROUNDS
            )["satisfied"],
        }
    published = generate_parameters(3, FULL_ROUNDS, PUBLISHED_WIDTH3_PARTIAL_ROUNDS)
    flat = [value for row in published[0] for value in row]
    if tuple(flat[:6]) != PUBLISHED_WIDTH3_FIRST_ROUND_CONSTANTS:
        raise ValueError("the generator does not reproduce the published width-three constants")
    if tuple(tuple(row) for row in published[1]) != PUBLISHED_WIDTH3_MDS:
        raise ValueError("the generator does not reproduce the published width-three MDS matrix")
    shared = sum(
        1
        for ours, theirs in zip(
            (value for row in tables[3][0] for value in row), flat
        )
        if ours == theirs
    )
    return {
        "field_modulus": str(BN254_FR),
        "field_bits": FIELD_BITS,
        "alpha": ALPHA,
        "security_bits": SECURITY_BITS,
        "total_field_elements": sum(entry["field_elements"] for entry in widths.values()),
        "widths": widths,
        "published_width3": {
            "source": "hadeshash code/poseidonperm_x5_254_3.sage",
            "full_rounds": FULL_ROUNDS,
            "partial_rounds": PUBLISHED_WIDTH3_PARTIAL_ROUNDS,
            "table_sha256": table_sha256(*published),
            "generator_reproduces_pinned_values": True,
            "round_constants_shared_with_repository": shared,
            "mds_equal_to_repository": published[1] == tables[3][1],
        },
        "vectors": reference_vectors(tables),
    }


def main(argv: Sequence[str] | None = None) -> int:
    """Run the regeneration and print the report or the vectors as JSON."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=ROOT, help="repository root")
    parser.add_argument("--print-vectors", action="store_true", help="print only the vectors")
    parser.add_argument(
        "--write-vectors",
        action="store_true",
        help=f"rewrite {VECTOR_FIXTURE} from the regenerated parameters",
    )
    args = parser.parse_args(argv)
    try:
        report = build_report(args.root)
        fixture = render_vector_fixture(report["vectors"])
        if args.write_vectors:
            (args.root / VECTOR_FIXTURE).write_text(fixture, encoding="utf-8")
        elif (args.root / VECTOR_FIXTURE).read_text(encoding="utf-8") != fixture:
            raise ValueError(f"{VECTOR_FIXTURE} differs from the regenerated vectors")
    except (OSError, ValueError) as error:
        print(f"BN254 Poseidon reference check failed: {error}", file=sys.stderr)
        return 1
    json.dump(report["vectors"] if args.print_vectors else report, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
