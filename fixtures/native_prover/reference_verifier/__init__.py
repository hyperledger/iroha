"""Independent standard-library PIPA reference verification from the protocol spec.

This is retained test evidence, never a production verifier or fallback decoder.
"""


class InvalidProof(ValueError):
    """A canonicality, protocol binding, or algebraic acceptance check failed."""


def require(condition: bool, reason: str) -> None:
    """Reject explicitly, including when Python runs with assertions disabled."""
    if not condition:
        raise InvalidProof(reason)
