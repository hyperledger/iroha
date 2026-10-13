"""Settlement helpers for delivery-versus-payment (DvP) and payment-versus-payment (PvP) flows."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Mapping, Optional, Union

from ._quantity import (
    QuantityLike,
    _normalize_positive_quantity,
    _normalize_quantity,
)


def _normalize_metadata(metadata: Optional[Mapping[str, Any]]) -> Optional[Mapping[str, Any]]:
    from .tx import _normalize_metadata as _tx_normalize_metadata

    return _tx_normalize_metadata(metadata)


__all__ = [
    "SettlementLeg",
    "SettlementPlan",
    "SettlementExecutionOrder",
    "SettlementAtomicity",
    "BatchMode",
    "Payment",
    "EscrowValue",
    "OracleCondition",
    "DeadlineCondition",
]


class BatchMode(str, Enum):
    """Commit behavior for one native multi-payment instruction."""

    ATOMIC = "Atomic"
    INDEPENDENT = "Independent"


@dataclass(frozen=True)
class Payment:
    """One correlated leg in a native batch transfer."""

    id: str
    to: str
    amount: Any

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not self.id or self.id.strip() != self.id:
            raise ValueError("payment id must be exact non-empty text")
        if not isinstance(self.to, str) or not self.to or self.to.strip() != self.to:
            raise ValueError("payment destination must be exact non-empty text")
        object.__setattr__(
            self,
            "amount",
            _normalize_positive_quantity(self.amount, "payment amount"),
        )

    def to_payload(self) -> dict[str, Any]:
        """Return the canonical native batch-leg payload."""

        return {"id": self.id, "to": self.to, "amount": self.amount}


@dataclass(frozen=True)
class EscrowValue:
    """One explicit typed value evaluated by a conditional escrow."""

    kind: str
    value: Any

    def __post_init__(self) -> None:
        if self.kind == "Bool":
            if not isinstance(self.value, bool):
                raise TypeError("Bool escrow value must be a bool")
            return
        if self.kind == "Text":
            if not isinstance(self.value, str):
                raise TypeError("Text escrow value must be a string")
            if not self.value or len(self.value.encode("utf-8")) > 1_024:
                raise ValueError("Text escrow value must contain 1..=1024 UTF-8 bytes")
            return
        if self.kind == "Quantity":
            if not isinstance(self.value, str) or not self.value:
                raise TypeError("Quantity escrow value must be a canonical quantity string")
            return
        raise ValueError("escrow value kind must be Bool, Text, or Quantity")

    @classmethod
    def boolean(cls, value: bool) -> "EscrowValue":
        return cls("Bool", value)

    @classmethod
    def text(cls, value: str) -> "EscrowValue":
        return cls("Text", value)

    @classmethod
    def quantity(cls, value: Any) -> "EscrowValue":
        if isinstance(value, bool):
            raise TypeError("Quantity escrow value must not be a bool")
        return cls("Quantity", _normalize_quantity(value))

    def to_payload(self) -> dict[str, Any]:
        return {"kind": self.kind, "value": self.value}


@dataclass(frozen=True)
class OracleCondition:
    """One immutable, ordered, attestor-bound predicate."""

    id: str
    predicate_kind: str
    predicate_value: Union[EscrowValue, str]
    attestor: str
    order: int

    def __post_init__(self) -> None:
        for value, name in ((self.id, "id"), (self.attestor, "attestor")):
            if not isinstance(value, str) or not value or value.strip() != value:
                raise ValueError(f"oracle condition {name} must be exact non-empty text")
        if isinstance(self.order, bool) or not isinstance(self.order, int) or self.order <= 0:
            raise ValueError("oracle condition order must be a positive integer")
        if self.predicate_kind == "Equals":
            if not isinstance(self.predicate_value, EscrowValue):
                raise TypeError("Equals predicate requires an EscrowValue")
        elif self.predicate_kind == "QuantityAtMost":
            if not isinstance(self.predicate_value, str) or not self.predicate_value:
                raise TypeError("QuantityAtMost predicate requires a quantity string")
        else:
            raise ValueError("predicate kind must be Equals or QuantityAtMost")

    @classmethod
    def equals(
        cls,
        claim: str,
        expected: EscrowValue,
        attestor: str,
        *,
        order: int,
    ) -> "OracleCondition":
        return cls(claim, "Equals", expected, attestor, order)

    @classmethod
    def quantity_at_most(
        cls,
        claim: str,
        maximum: Any,
        attestor: str,
        *,
        order: int,
    ) -> "OracleCondition":
        return cls(
            claim,
            "QuantityAtMost",
            _normalize_quantity(maximum),
            attestor,
            order,
        )

    def to_payload(self) -> dict[str, Any]:
        predicate_value = (
            self.predicate_value.to_payload()
            if isinstance(self.predicate_value, EscrowValue)
            else self.predicate_value
        )
        return {
            "kind": "Oracle",
            "value": {
                "id": self.id,
                "attestor": self.attestor,
                "predicate": {
                    "kind": self.predicate_kind,
                    "value": predicate_value,
                },
                "sequence": self.order,
            },
        }


@dataclass(frozen=True)
class DeadlineCondition:
    """Ledger-time deadline relative to escrow creation."""

    id: str
    duration_ms: int

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not self.id or self.id.strip() != self.id:
            raise ValueError("deadline id must be exact non-empty text")
        if (
            isinstance(self.duration_ms, bool)
            or not isinstance(self.duration_ms, int)
            or self.duration_ms <= 0
        ):
            raise ValueError("deadline duration_ms must be a positive integer")

    @classmethod
    def within(
        cls,
        *,
        days: int = 0,
        hours: int = 0,
        minutes: int = 0,
        seconds: int = 0,
        milliseconds: int = 0,
        id: str = "deadline",
    ) -> "DeadlineCondition":
        parts = {
            "days": days,
            "hours": hours,
            "minutes": minutes,
            "seconds": seconds,
            "milliseconds": milliseconds,
        }
        for name, value in parts.items():
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        duration_ms = (
            days * 86_400_000
            + hours * 3_600_000
            + minutes * 60_000
            + seconds * 1_000
            + milliseconds
        )
        if duration_ms <= 0:
            raise ValueError("deadline duration must be positive")
        return cls(id=id, duration_ms=duration_ms)

    def to_payload(self) -> dict[str, Any]:
        return {
            "kind": "Within",
            "value": {"id": self.id, "duration_ms": self.duration_ms},
        }


class SettlementExecutionOrder(str, Enum):
    """Execution ordering between the two settlement legs."""

    DELIVERY_THEN_PAYMENT = "delivery_then_payment"
    PAYMENT_THEN_DELIVERY = "payment_then_delivery"


class SettlementAtomicity(str, Enum):
    """All-or-nothing policy for native bilateral settlement."""

    ALL_OR_NOTHING = "all_or_nothing"


@dataclass(frozen=True)
class SettlementPlan:
    """Plan describing execution ordering and atomicity semantics."""

    order: SettlementExecutionOrder = SettlementExecutionOrder.DELIVERY_THEN_PAYMENT
    atomicity: SettlementAtomicity = SettlementAtomicity.ALL_OR_NOTHING

    def to_payload(self) -> Mapping[str, Any]:
        return {
            "order": self.order.value,
            "atomicity": self.atomicity.value,
        }


@dataclass(frozen=True)
class SettlementLeg:
    """One leg of a bilateral settlement."""

    asset_definition_id: str
    quantity: QuantityLike
    from_account: str
    to_account: str
    metadata: Optional[Mapping[str, Any]] = None

    def to_payload(self) -> Mapping[str, Any]:
        payload: Dict[str, Any] = {
            "asset_definition_id": self.asset_definition_id,
            "quantity": _normalize_quantity(self.quantity),
            "from": self.from_account,
            "to": self.to_account,
        }
        if self.metadata:
            payload["metadata"] = _normalize_metadata(self.metadata)
        return payload
