"""Repo agreement helpers and dataclasses."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional

from ._quantity import QuantityLike, _normalize_quantity
from .numeric_v1 import NumericV1Codec


def _decode_quantity(value: Any, context: str) -> str:
    if type(value) is not str:
        raise TypeError(f"{context} must be a canonical JSON string")
    if len(value) > 155:
        raise ValueError(f"{context} exceeds the canonical V1 text bound")
    return str(NumericV1Codec.decode_quantity_json(value))


def _normalize_metadata(metadata: Optional[Mapping[str, Any]]) -> Optional[Mapping[str, Any]]:
    from .tx import _normalize_metadata as _tx_normalize_metadata

    return _tx_normalize_metadata(metadata)


__all__ = [
    "RepoCashLeg",
    "RepoCollateralLeg",
    "RepoGovernance",
    "RepoAgreementRecord",
]


@dataclass(frozen=True)
class RepoCashLeg:
    """Cash consideration exchanged during repo initiation and unwind."""

    asset_definition_id: str
    quantity: QuantityLike
    metadata: Optional[Mapping[str, Any]] = None

    def to_payload(self) -> Mapping[str, Any]:
        payload: Dict[str, Any] = {
            "asset_definition_id": self.asset_definition_id,
            "quantity": _normalize_quantity(self.quantity),
        }
        if self.metadata:
            payload["metadata"] = _normalize_metadata(self.metadata)
        return payload


@dataclass(frozen=True)
class RepoCollateralLeg:
    """Collateral pledged for the repo lifecycle."""

    asset_definition_id: str
    quantity: QuantityLike
    metadata: Optional[Mapping[str, Any]] = None

    def to_payload(self) -> Mapping[str, Any]:
        payload: Dict[str, Any] = {
            "asset_definition_id": self.asset_definition_id,
            "quantity": _normalize_quantity(self.quantity),
        }
        if self.metadata:
            payload["metadata"] = _normalize_metadata(self.metadata)
        return payload


@dataclass(frozen=True)
class RepoGovernance:
    """Governance parameters controlling haircuts, margin cadence and early repayment.

    ``allow_early_repayment`` is part of both consent hashes. When set, only the
    initiator (cash borrower) may settle before maturity, paying interest accrued
    to the committed block time.
    """

    haircut_bps: int
    margin_frequency_secs: int
    allow_early_repayment: bool

    def to_payload(self) -> Mapping[str, Any]:
        if type(self.allow_early_repayment) is not bool:
            raise TypeError("repo governance.allow_early_repayment must be a boolean")
        return {
            "haircut_bps": int(self.haircut_bps),
            "margin_frequency_secs": int(self.margin_frequency_secs),
            "allow_early_repayment": self.allow_early_repayment,
        }

    def margin_frequency_millis(self) -> Optional[int]:
        """Return the margin frequency in milliseconds, or ``None`` when disabled."""

        if self.margin_frequency_secs <= 0:
            return None
        return int(self.margin_frequency_secs) * 1_000


@dataclass(frozen=True)
class RepoAgreementRecord:
    """Snapshot of a repo agreement stored on-chain."""

    agreement_id: str
    initiator: str
    counterparty: str
    custodian: Optional[str]
    cash_leg: RepoCashLeg
    cash_source: str
    collateral_leg: RepoCollateralLeg
    collateral_custody_asset: str
    rate_bps: int
    maturity_timestamp_ms: int
    initiated_timestamp_ms: int
    last_margin_check_timestamp_ms: int
    governance: RepoGovernance
    settlement_timestamp_ms: Optional[int]
    status: str

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "RepoAgreementRecord":
        """Construct a record from the Torii JSON payload."""

        def require(name: str) -> Any:
            if name not in payload:
                raise KeyError(f"repo agreement payload missing `{name}` field")
            return payload[name]

        cash_payload = require("cash_leg")
        collateral_payload = require("collateral_leg")
        governance_payload = require("governance")
        if not isinstance(cash_payload, Mapping):
            raise TypeError("repo cash_leg must be an object")
        if not isinstance(collateral_payload, Mapping):
            raise TypeError("repo collateral_leg must be an object")
        if not isinstance(governance_payload, Mapping):
            raise TypeError("repo governance must be an object")
        if "quantity" not in cash_payload:
            raise KeyError("repo cash_leg payload missing `quantity` field")
        if "quantity" not in collateral_payload:
            raise KeyError("repo collateral_leg payload missing `quantity` field")
        cash_leg = RepoCashLeg(
            asset_definition_id=_require_non_empty_string(
                cash_payload.get("asset_definition_id"), "repo cash_leg.asset_definition_id"
            ),
            quantity=_decode_quantity(cash_payload["quantity"], "repo cash_leg.quantity"),
            metadata=_normalize_metadata(cash_payload.get("metadata")),
        )
        collateral_meta = collateral_payload.get("metadata")
        collateral_leg = RepoCollateralLeg(
            asset_definition_id=_require_non_empty_string(
                collateral_payload.get("asset_definition_id"), "repo collateral_leg.asset_definition_id"
            ),
            quantity=_decode_quantity(
                collateral_payload["quantity"],
                "repo collateral_leg.quantity",
            ),
            metadata=_normalize_metadata(collateral_meta),
        )
        allow_early_repayment = governance_payload.get("allow_early_repayment")
        if type(allow_early_repayment) is not bool:
            raise TypeError("repo governance.allow_early_repayment must be a boolean")
        governance = RepoGovernance(
            haircut_bps=_coerce_int_field(governance_payload.get("haircut_bps"), "repo governance.haircut_bps"),
            margin_frequency_secs=_coerce_int_field(
                governance_payload.get("margin_frequency_secs"), "repo governance.margin_frequency_secs", allow_zero=True
            ),
            allow_early_repayment=allow_early_repayment,
        )
        custodian = payload.get("custodian")
        if custodian is not None:
            custodian = _require_non_empty_string(custodian, "repo custodian")

        initiated_timestamp_ms = _coerce_int_field(
            payload.get("initiated_timestamp_ms"),
            "repo initiated_timestamp_ms",
            allow_zero=True,
        )
        maturity_timestamp_ms = _coerce_int_field(
            payload.get("maturity_timestamp_ms"),
            "repo maturity_timestamp_ms",
            allow_zero=True,
        )
        last_margin_literal = payload.get("last_margin_check_timestamp_ms")
        if last_margin_literal is None:
            last_margin_check_timestamp_ms = initiated_timestamp_ms
        else:
            last_margin_check_timestamp_ms = _coerce_int_field(
                last_margin_literal,
                "repo last_margin_check_timestamp_ms",
                allow_zero=True,
            )
        if last_margin_check_timestamp_ms < initiated_timestamp_ms:
            last_margin_check_timestamp_ms = initiated_timestamp_ms
        settlement_literal = require("settlement_timestamp_ms")
        settlement_timestamp_ms = (
            None
            if settlement_literal is None
            else _coerce_int_field(
                settlement_literal,
                "repo settlement_timestamp_ms",
                allow_zero=True,
            )
        )
        status = _require_non_empty_string(require("status"), "repo status")
        expected_status = "active" if settlement_timestamp_ms is None else "settled"
        if status != expected_status:
            raise ValueError(
                "repo status must agree with settlement_timestamp_ms "
                f"(expected {expected_status!r})"
            )
        return cls(
            agreement_id=_require_non_empty_string(require("id"), "repo agreement id"),
            initiator=_require_non_empty_string(require("initiator"), "repo agreement initiator"),
            counterparty=_require_non_empty_string(require("counterparty"), "repo agreement counterparty"),
            custodian=custodian,
            cash_leg=cash_leg,
            cash_source=_require_non_empty_string(require("cash_source"), "repo cash_source"),
            collateral_leg=collateral_leg,
            collateral_custody_asset=_require_non_empty_string(
                require("collateral_custody_asset"),
                "repo collateral_custody_asset",
            ),
            rate_bps=_coerce_int_field(require("rate_bps"), "repo rate_bps", allow_zero=True),
            maturity_timestamp_ms=maturity_timestamp_ms,
            initiated_timestamp_ms=initiated_timestamp_ms,
            last_margin_check_timestamp_ms=last_margin_check_timestamp_ms,
            governance=governance,
            settlement_timestamp_ms=settlement_timestamp_ms,
            status=status,
        )

    def next_margin_check_after(self, after_timestamp_ms: int) -> Optional[int]:
        """Compute the next margin checkpoint strictly after the provided timestamp."""

        frequency_ms = self.governance.margin_frequency_millis()
        if frequency_ms is None:
            return None
        start = int(self.last_margin_check_timestamp_ms)
        if after_timestamp_ms < start:
            return start
        elapsed = after_timestamp_ms - start
        periods_elapsed = elapsed // frequency_ms
        next_period = periods_elapsed + 1
        return start + frequency_ms * next_period

    def is_margin_check_due(self, at_timestamp_ms: int) -> bool:
        """Return ``True`` when a margin call is due at the provided timestamp."""

        next_due = self.next_margin_check_after(int(self.last_margin_check_timestamp_ms))
        if next_due is None:
            return False
        return at_timestamp_ms >= next_due

    def to_payload(self) -> Mapping[str, Any]:
        """Render a JSON-serialisable view of the agreement."""

        payload = {
            "id": self.agreement_id,
            "initiator": self.initiator,
            "counterparty": self.counterparty,
            "custodian": self.custodian,
            "cash_leg": self.cash_leg.to_payload(),
            "cash_source": self.cash_source,
            "collateral_leg": self.collateral_leg.to_payload(),
            "collateral_custody_asset": self.collateral_custody_asset,
            "rate_bps": int(self.rate_bps),
            "maturity_timestamp_ms": int(self.maturity_timestamp_ms),
            "initiated_timestamp_ms": int(self.initiated_timestamp_ms),
            "last_margin_check_timestamp_ms": int(self.last_margin_check_timestamp_ms),
            "governance": self.governance.to_payload(),
            "settlement_timestamp_ms": self.settlement_timestamp_ms,
            "status": self.status,
        }
        return payload


def _require_non_empty_string(value: Any, context: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{context} must be a string")
    trimmed = value.strip()
    if not trimmed:
        raise ValueError(f"{context} must be non-empty")
    return trimmed


def _coerce_int_field(value: Any, context: str, *, allow_zero: bool = False) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise TypeError(f"{context} must be numeric") from exc
    if number < 0 or (number == 0 and not allow_zero):
        raise ValueError(f"{context} must be positive")
    return number
