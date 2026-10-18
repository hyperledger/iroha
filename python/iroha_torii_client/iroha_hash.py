"""Canonical Iroha Blake2b-256 hash bytes for active protocol identities."""
import hashlib


def iroha_hash_bytes(payload: bytes) -> bytes:
    """Hash bytes with the canonical Iroha low marker bit."""
    digest = bytearray(hashlib.blake2b(payload, digest_size=32).digest())
    digest[-1] |= 1
    return bytes(digest)
