"""Automatic Poseidon parity; CPU fallback is valid and does not qualify CUDA."""

import pytest

from iroha_python import gpu

MAX = (1 << 64) - 1


@pytest.mark.parametrize("width,rows,expected", [
    (2, [(0, 0), (1, 0), (0, 1), (1, 1), (MAX, MAX)],
     (0x541BC08E21EA84D9, 0xF0E5B21608C24308, 0x70C2D9E7D4787F50,
      0x6CE751F52456CDF3, 0x2A3B041A8625F023)),
    (6, [(0,) * 6, (1, 2, 3, 4, 5, 6), (1, 0, 0, 0, 0, 0),
         (0, 1, 0, 0, 0, 0), (MAX,) * 6],
     (0x63006C10F267D188, 0xE56F9EE6B038389A, 0xD8C9B0FCF7499786,
      0x819B7CDD16319D0F, 0xE4F413EC7EE962AD)),
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
