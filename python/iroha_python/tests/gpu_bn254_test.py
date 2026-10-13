"""Automatic BN254 Python/native contract; these tests do not qualify CUDA hardware."""

import operator

import pytest

from iroha_python import gpu

MODULUS = 0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001


def limbs(value):
    return tuple((value >> (index * 64)) & ((1 << 64) - 1) for index in range(4))


@pytest.mark.parametrize("name,relation", [("add", operator.add), ("sub", operator.sub), ("mul", operator.mul)])
def test_automatic_batch_matches_full_width_reference_without_device_requirement(name, relation):
    operation = getattr(gpu, f"bn254_{name}_many")
    left = [0, 1, MODULUS - 1, (1 << 192) - 1]
    right = [MODULUS - 1, 2, MODULUS - 1, (1 << 128) + 1]
    assert operation([limbs(value) for value in left], [limbs(value) for value in right]) == tuple(
        limbs(relation(a, b) % MODULUS) for a, b in zip(left, right, strict=True)
    )
    assert operation([], []) == ()
    assert not hasattr(gpu, f"bn254_{name}_cuda_many")


@pytest.mark.parametrize("name", ["add", "sub", "mul"])
def test_batch_rejects_noncanonical_limbs_and_lengths(name):
    operation = getattr(gpu, f"bn254_{name}_many")
    for invalid in [limbs(MODULUS), (-1, 0, 0, 0), (1 << 64, 0, 0, 0), (True, 0, 0, 0), (0, 0, 0)]:
        with pytest.raises(ValueError):
            operation([invalid], [limbs(0)])
    with pytest.raises(TypeError):
        operation([(1.5, 0, 0, 0)], [limbs(0)])
    with pytest.raises(ValueError):
        operation([limbs(0)], [])
