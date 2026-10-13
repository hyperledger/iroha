"""Automatic BN254/Poseidon batches and explicit CUDA diagnostics from the native extension."""

from __future__ import annotations

from operator import index as integer_index
from typing import Optional, Sequence, Tuple

from iroha_native import load_crypto_extension

_crypto = load_crypto_extension()

__all__ = [
    "cuda_available",
    "cuda_disabled",
    "poseidon2_cuda",
    "poseidon2_many",
    "poseidon6_cuda",
    "poseidon6_many",
    "bn254_add_cuda",
    "bn254_add_many",
    "bn254_sub_cuda",
    "bn254_sub_many",
    "bn254_mul_cuda",
    "bn254_mul_many",
]


def cuda_available() -> bool:
    """Return ``True`` when the CUDA backend initialised successfully."""

    return bool(_crypto.cuda_available())


def cuda_disabled() -> bool:
    """Return ``True`` when the CUDA backend has been disabled after a failure."""

    return bool(_crypto.cuda_disabled())


def poseidon2_cuda(a: int, b: int) -> Optional[int]:
    """Execute the Poseidon2 permutation via CUDA when available.

    Returns ``None`` when CUDA support is unavailable or the backend has been disabled.
    """

    result = _crypto.poseidon2_cuda(int(a), int(b))
    return int(result) if result is not None else None


def poseidon2_many(pairs: Sequence[Sequence[int]]) -> Tuple[int, ...]:
    """Compute ordered 2-word Poseidon rows with automatic CPU/GPU selection."""

    rows = _expect_poseidon_rows(pairs, 2)
    return tuple(integer_index(value) for value in _crypto.poseidon2_many(rows))


def poseidon6_cuda(inputs: Sequence[int]) -> Optional[int]:
    """Execute the Poseidon6 permutation via CUDA when available.

    The ``inputs`` sequence must contain exactly six integers representing field elements.
    Returns ``None`` when CUDA support is unavailable or the backend has been disabled.
    """

    if len(inputs) != 6:
        raise ValueError("poseidon6_cuda expects exactly six input elements")
    result = _crypto.poseidon6_cuda(tuple(int(value) for value in inputs))
    return int(result) if result is not None else None


def poseidon6_many(inputs: Sequence[Sequence[int]]) -> Tuple[int, ...]:
    """Compute ordered 6-word Poseidon rows with automatic CPU/GPU selection."""

    rows = _expect_poseidon_rows(inputs, 6)
    return tuple(integer_index(value) for value in _crypto.poseidon6_many(rows))


def _expect_poseidon_rows(rows: Sequence[Sequence[int]], width: int) -> Tuple[Tuple[int, ...], ...]:
    result = []
    for row in rows:
        if len(row) != width:
            raise ValueError(f"Poseidon input rows must contain {width} words")
        words = tuple(integer_index(value) for value in row)
        if any(isinstance(value, bool) for value in row) or any(value < 0 or value >= 1 << 64 for value in words):
            raise ValueError("Poseidon inputs must be unsigned 64-bit integer words")
        result.append(words)
    return tuple(result)


def _expect_field_elem(elem: Sequence[int], context: str) -> Tuple[int, int, int, int]:
    if len(elem) != 4:
        raise ValueError(f"{context} expects four 64-bit limbs")
    words = tuple(integer_index(value) for value in elem)
    if any(isinstance(value, bool) for value in elem) or any(value < 0 or value >= 1 << 64 for value in words):
        raise ValueError(f"{context} expects unsigned 64-bit integer limbs")
    modulus = 0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001
    if sum(value << (64 * index) for index, value in enumerate(words)) >= modulus:
        raise ValueError(f"{context} must be below the BN254 field modulus")
    return words[0], words[1], words[2], words[3]



def _expect_field_elem_many(
    elems: Sequence[Sequence[int]], context: str
) -> Tuple[Tuple[int, int, int, int], ...]:
    return tuple(_expect_field_elem(elem, context) for elem in elems)


def bn254_add_cuda(a: Sequence[int], b: Sequence[int]) -> Optional[Tuple[int, int, int, int]]:
    """Add two BN254 field elements using the CUDA backend when available."""

    result = _crypto.bn254_add_cuda(_expect_field_elem(a, "bn254_add_cuda"), _expect_field_elem(b, "bn254_add_cuda"))
    if result is None:
        return None
    return _expect_field_elem(result, "bn254_add_cuda result")


def bn254_add_many(
    lhs: Sequence[Sequence[int]], rhs: Sequence[Sequence[int]]
) -> Tuple[Tuple[int, int, int, int], ...]:
    """Add canonical BN254 rows with automatic CPU/GPU selection.

    Invalid rows raise ``ValueError``; local native resource refusal raises
    ``MemoryError``. Empty batches return an empty tuple without a GPU.
    """

    if len(lhs) != len(rhs):
        raise ValueError("bn254_add_many expects matching batch lengths")
    result = _crypto.bn254_add_many(
        _expect_field_elem_many(lhs, "bn254_add_many lhs"),
        _expect_field_elem_many(rhs, "bn254_add_many rhs"),
    )
    return tuple(_expect_field_elem(elem, "bn254_add_many result") for elem in result)


def bn254_sub_cuda(a: Sequence[int], b: Sequence[int]) -> Optional[Tuple[int, int, int, int]]:
    """Subtract two BN254 field elements using the CUDA backend when available."""

    result = _crypto.bn254_sub_cuda(_expect_field_elem(a, "bn254_sub_cuda"), _expect_field_elem(b, "bn254_sub_cuda"))
    if result is None:
        return None
    return _expect_field_elem(result, "bn254_sub_cuda result")


def bn254_sub_many(
    lhs: Sequence[Sequence[int]], rhs: Sequence[Sequence[int]]
) -> Tuple[Tuple[int, int, int, int], ...]:
    """Subtract canonical BN254 rows with automatic CPU/GPU selection.

    Invalid rows raise ``ValueError``; local native resource refusal raises
    ``MemoryError``. Empty batches return an empty tuple without a GPU.
    """

    if len(lhs) != len(rhs):
        raise ValueError("bn254_sub_many expects matching batch lengths")
    result = _crypto.bn254_sub_many(
        _expect_field_elem_many(lhs, "bn254_sub_many lhs"),
        _expect_field_elem_many(rhs, "bn254_sub_many rhs"),
    )
    return tuple(_expect_field_elem(elem, "bn254_sub_many result") for elem in result)


def bn254_mul_cuda(a: Sequence[int], b: Sequence[int]) -> Optional[Tuple[int, int, int, int]]:
    """Multiply two BN254 field elements using the CUDA backend when available."""

    result = _crypto.bn254_mul_cuda(_expect_field_elem(a, "bn254_mul_cuda"), _expect_field_elem(b, "bn254_mul_cuda"))
    if result is None:
        return None
    return _expect_field_elem(result, "bn254_mul_cuda result")


def bn254_mul_many(
    lhs: Sequence[Sequence[int]], rhs: Sequence[Sequence[int]]
) -> Tuple[Tuple[int, int, int, int], ...]:
    """Multiply canonical BN254 rows with automatic CPU/GPU selection.

    Invalid rows raise ``ValueError``; local native resource refusal raises
    ``MemoryError``. Empty batches return an empty tuple without a GPU.
    """

    if len(lhs) != len(rhs):
        raise ValueError("bn254_mul_many expects matching batch lengths")
    result = _crypto.bn254_mul_many(
        _expect_field_elem_many(lhs, "bn254_mul_many lhs"),
        _expect_field_elem_many(rhs, "bn254_mul_many rhs"),
    )
    return tuple(_expect_field_elem(elem, "bn254_mul_many result") for elem in result)
