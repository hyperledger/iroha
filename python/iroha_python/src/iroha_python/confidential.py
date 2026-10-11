"""Local confidential proving with automatic circuit and key selection.

The native owner clears its private allocations and releases the Python GIL
during proving. Python bytes and interpreter copies have no erasure guarantee.
Proofs are locally verified material; ledger admission and authorization remain
the responsibility of the protocol that consumes them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, Mapping

if TYPE_CHECKING:
    from .crypto import NetworkId


class ConfidentialProverError(RuntimeError):
    """A wallet failure with a stable ``code`` for programmatic handling."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, repr=False)
class ConfidentialInput:
    """An owned note opening; supply only actual notes, without dummy inputs."""

    amount: int
    rho: bytes
    diversifier: bytes
    leaf_index: int


@dataclass(frozen=True, repr=False)
class ConfidentialOutput:
    """A new transfer note with a securely random nonce and recipient owner tag."""

    amount: int
    rho: bytes
    owner_tag: bytes


@dataclass(frozen=True, repr=False)
class ConfidentialChange:
    """Private change; retain this opening and use ``to_input`` when spending it."""

    amount: int
    rho: bytes

    def to_input(self, leaf_index: int) -> ConfidentialInput:
        """Use the change owner's native diversifier and its authenticated tree index.

        Change belongs to the spending wallet's default owner, independently of
        the consumed notes' diversifiers. This creates local note data only.
        """
        if type(leaf_index) is not int or not 0 <= leaf_index < 65536:
            raise ConfidentialProverError("invalid_input", "change leaf index is outside the tree")
        from .crypto import default_confidential_diversifier_v2

        return ConfidentialInput(self.amount, self.rho, default_confidential_diversifier_v2(), leaf_index)


@dataclass(frozen=True, repr=False)
class ConfidentialTree:
    """Authenticated root and either complete leaves or one path per input.

    Each path contains ``root: bytes``, sixteen ``siblings: bytes`` and sixteen
    integer ``directions`` (0 or 1), ordered from leaf to root. Obtain the root
    from authenticated ledger state, independently of the proof producer.
    """

    root: bytes
    commitments: list[bytes] | tuple[bytes, ...] | None = None
    paths: list[Mapping[str, object]] | tuple[Mapping[str, object], ...] | None = None

    def _arguments(self) -> dict[str, object]:
        if (self.commitments is None) == (self.paths is None):
            raise ConfidentialProverError(
                "invalid_input", "supply either complete commitments or input paths"
            )
        if self.commitments is not None:
            return {"root": self.root, "tree_commitments": _sequence(self.commitments, 65536)}
        return {"root": self.root, "input_paths": _sequence(self.paths, 2)}


@dataclass(frozen=True)
class ConfidentialProof:
    """Public output of a native, locally verified proof; no transaction is sent."""

    relation: Literal["transfer", "full_redemption", "redemption_with_change"]
    backend: str
    proof: bytes
    root: bytes
    nullifiers: tuple[bytes, ...]
    output_commitments: tuple[bytes, ...]


def _sequence(value: object, maximum: int) -> list:
    if not isinstance(value, (list, tuple)) or len(value) > maximum:
        raise ConfidentialProverError(
            "invalid_input", f"supply a list or tuple with at most {maximum} items"
        )
    return list(value)


def _note(value: object, kind: type) -> dict[str, object]:
    if not isinstance(value, kind):
        raise ConfidentialProverError("invalid_input", f"expected {kind.__name__}")
    # Copy references only; do not use dataclasses.asdict, which deep-copies inputs.
    return {name: getattr(value, name) for name in kind.__dataclass_fields__}


class ConfidentialProver:
    """Bind a wallet to an exact network, canonical asset and 32-byte spend key.

    Use as a context manager or call ``close()``. Closing prevents new work;
    already running native work retains its key until completion. Methods block
    the calling thread while releasing the GIL. In asyncio applications use
    ``await asyncio.to_thread(prover.prove_unshield, ...)``.
    """

    def __init__(self, network_id: NetworkId, asset_definition_id: str, spend_key: bytes):
        from .crypto import _crypto, _require_network_id

        if not hasattr(_crypto, "ConfidentialProver"):
            raise ConfidentialProverError(
                "native_unavailable", "rebuild the native extension for confidential wallet proving"
            )
        self._native_error = _crypto.ConfidentialWalletError
        self._owner = None
        try:
            self._owner = _crypto.ConfidentialProver(
                _require_network_id(network_id), asset_definition_id, spend_key
            )
        except self._native_error as error:
            raise self._error(error) from error

    @staticmethod
    def _error(error: Exception) -> ConfidentialProverError:
        if len(error.args) == 2 and all(isinstance(part, str) for part in error.args):
            return ConfidentialProverError(error.args[0], error.args[1])
        return ConfidentialProverError("internal", "unexpected native wallet failure")

    def __repr__(self) -> str:
        return "ConfidentialProver(private_context=[REDACTED])"

    def __copy__(self):
        raise TypeError("confidential prover cannot be copied")

    def __deepcopy__(self, memo):
        raise TypeError("confidential prover cannot be copied")

    def __getstate__(self):
        raise TypeError("confidential prover cannot be serialized")

    def __enter__(self) -> ConfidentialProver:
        self._require_owner()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()

    def _require_owner(self):
        if self._owner is None:
            raise ConfidentialProverError("closed", "confidential prover is closed")
        return self._owner

    def close(self) -> None:
        """Release the private native owner; repeated closure is harmless."""
        owner = self._owner
        if owner is not None:
            try:
                owner.close()
            except self._native_error as error:
                raise self._error(error) from error
            self._owner = None

    def _prove(self, operation: str, arguments: dict[str, object]) -> ConfidentialProof:
        owner = self._require_owner()
        try:
            result = getattr(owner, operation)(**arguments)
        except self._native_error as error:
            raise self._error(error) from error
        try:
            proof = ConfidentialProof(
                relation=result["relation"],
                backend=result["backend"],
                proof=result["proof"],
                root=result["root"],
                nullifiers=tuple(result["nullifiers"]),
                output_commitments=tuple(result["output_commitments"]),
            )
            if (
                proof.root != arguments["root"]
                or proof.backend != "pipa-r/pasta"
                or not isinstance(proof.proof, bytes)
                or not proof.proof
            ):
                raise ValueError("native proof output does not match the requested root")
            if len(proof.nullifiers) != len(arguments["inputs"]):
                raise ValueError("native proof input cardinality mismatch")
            expected = (
                len(arguments["outputs"])
                if operation == "prove_transfer"
                else int(arguments["change_note"] is not None)
            )
            expected_relation = (
                "transfer"
                if operation == "prove_transfer"
                else ("redemption_with_change" if expected else "full_redemption")
            )
            if len(proof.output_commitments) != expected or proof.relation != expected_relation:
                raise ValueError("native proof relation or output cardinality mismatch")
            if any(
                not isinstance(word, bytes) or len(word) != 32
                for word in (*proof.nullifiers, *proof.output_commitments)
            ):
                raise ValueError("native proof contains malformed public words")
            return proof
        except (KeyError, TypeError, ValueError) as error:
            raise ConfidentialProverError(
                "native_output", "native wallet returned malformed proof material"
            ) from error

    def prove_transfer(
        self,
        *,
        tree: ConfidentialTree,
        inputs: list[ConfidentialInput] | tuple[ConfidentialInput, ...],
        outputs: list[ConfidentialOutput] | tuple[ConfidentialOutput, ...],
    ) -> ConfidentialProof:
        """Prove a transfer; Core checks ownership, membership and conservation."""
        self._require_owner()
        if not isinstance(tree, ConfidentialTree):
            raise ConfidentialProverError("invalid_input", "expected ConfidentialTree")
        return self._prove(
            "prove_transfer",
            {
                **tree._arguments(),
                "inputs": [_note(note, ConfidentialInput) for note in _sequence(inputs, 2)],
                "outputs": [_note(note, ConfidentialOutput) for note in _sequence(outputs, 2)],
            },
        )

    def prove_unshield(
        self,
        *,
        tree: ConfidentialTree,
        inputs: list[ConfidentialInput] | tuple[ConfidentialInput, ...],
        public_amount: int,
        change: ConfidentialChange | None = None,
    ) -> ConfidentialProof:
        """Redeem value, selecting full redemption or private change automatically."""
        self._require_owner()
        if not isinstance(tree, ConfidentialTree):
            raise ConfidentialProverError("invalid_input", "expected ConfidentialTree")
        return self._prove(
            "prove_unshield",
            {
                **tree._arguments(),
                "inputs": [_note(note, ConfidentialInput) for note in _sequence(inputs, 2)],
                "public_amount": public_amount,
                "change_note": None if change is None else _note(change, ConfidentialChange),
            },
        )
