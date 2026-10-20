"""Automatic Poseidon parity; CPU fallback is valid and does not qualify CUDA."""

import pytest

from iroha_python import gpu

MAX = (1 << 64) - 1

# Independent circomlib v0.1.7 tables: arity << 64 capacity, additive absorption,
# output1 low64; six words use two rate-five blocks. No CUDA qualification.


@pytest.mark.parametrize("width,rows,expected", [
    (2, [(0, 0), (1, 0), (0, 1), (1, 1), (MAX, MAX)],
     (0x291EF55CED504E95, 0x7E84E4660F9C8602, 0xBE233AE487CC493C,
      0xC129BE072C4B4483, 0xC389DA81DBDDAE68)),
    (6, [(0,) * 6, (1, 2, 3, 4, 5, 6), (1, 0, 0, 0, 0, 0),
         (0, 1, 0, 0, 0, 0), (MAX,) * 6],
     (0xB5284C49A2AA43DD, 0xEA5537703DA851EC, 0x44126D1870284F85,
      0x741CDCA6D19888B3, 0x732EC89A4E972A38)),
])
def test_automatic_batch_matches_ivm_goldens(width, rows, expected):
    operation = getattr(gpu, f"poseidon{width}_many")
    assert operation(rows) == expected
    assert operation([]) == ()
    for row, result in zip(rows, expected, strict=True):
        assert operation([row]) == (result,)
    assert not hasattr(gpu, f"poseidon{width}_cuda_many")


@pytest.mark.parametrize("width", [2, 6])
def test_invalid_rows_reject_before_native_call(width, monkeypatch):
    def unexpected(*args):
        raise AssertionError("malformed row reached native computation")
    monkeypatch.setattr(gpu._crypto, f"poseidon{width}_many", unexpected)
    operation = getattr(gpu, f"poseidon{width}_many")
    with pytest.raises(ValueError):
        operation([(0,) * (width - 1)])
    for invalid in [-1, 1 << 64, True]:
        with pytest.raises(ValueError):
            operation([(invalid,) + (0,) * (width - 1)])
    with pytest.raises(TypeError):
        operation([(1.5,) + (0,) * (width - 1)])
