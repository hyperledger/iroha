"""Strict public bindings for native scheduled contract callbacks.

Positive canonical-wire preservation is covered in the native module tests.
These tests intentionally require the rebuilt native binding; no stub fallback.
"""

import pytest

from iroha_python import Ed25519KeyPair, Instruction


def kwargs():
    return dict(
        start_ms=10_000, period_ms=5_000, max_retries=3, retry_after_ms=5_000,
        chain_discriminant=753,
    )


def args():
    return (
        "boi.job.fixture",
        Ed25519KeyPair.from_private_key(bytes([0x71]) * 32).account_id(discriminant=753),
        "irohac1qyqqqqqqqqqqqqputuv64zhf0a0a4hhlqdj2lhnwuzq4xjq3qexfh",
        "01" * 32,
        "execute_scheduled_payment",
        b"",
    )


@pytest.mark.parametrize("field", ["start_ms", "period_ms", "max_retries", "retry_after_ms"])
@pytest.mark.parametrize("bad", [True, False, 0, -1, "3", 3.0, 1 << 65])
def test_scheduled_contract_call_rejects_noncanonical_schedule_numbers(field, bad):
    options = kwargs()
    options[field] = bad
    with pytest.raises((TypeError, ValueError, OverflowError)):
        Instruction.register_scheduled_contract_call(*args(), **options)


@pytest.mark.parametrize("arguments", [b"", b"not a canonical argument record", bytearray(b"x"), [1, 2]])
def test_scheduled_contract_call_requires_immutable_canonical_argument_bytes(arguments):
    selected = list(args())
    selected[-1] = arguments
    with pytest.raises((TypeError, ValueError)):
        Instruction.register_scheduled_contract_call(*selected, **kwargs())


@pytest.mark.parametrize("prefix", [True, -1, 65536, "753", 753.0, 117])
def test_scheduled_contract_call_requires_selected_account_presentation(prefix):
    options = kwargs()
    options["chain_discriminant"] = prefix
    with pytest.raises((TypeError, ValueError)):
        Instruction.register_scheduled_contract_call(*args(), **options)
