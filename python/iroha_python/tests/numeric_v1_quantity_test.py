"""Native-extension-free coverage for Numeric V1 quantity builders and readers."""

from __future__ import annotations

import subprocess
import sys
from decimal import Decimal
from pathlib import Path

import pytest

from iroha_python._quantity import _normalize_quantity
from iroha_python.numeric_v1 import KotodamaQuantity
from iroha_python.repo import (
    RepoAgreementRecord,
    RepoCashLeg,
    RepoCollateralLeg,
)
from iroha_python.settlement import SettlementLeg


def test_quantity_modules_do_not_load_native_crypto() -> None:
    package_root = Path(__file__).resolve().parents[1] / "src" / "iroha_python"
    norito_root = Path(__file__).resolve().parents[3] / "python" / "norito_py" / "src"
    probe = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import sys, types; sys.path.insert(0, sys.argv[2]); "
                "package = types.ModuleType('iroha_python'); "
                "package.__path__ = [sys.argv[1]]; "
                "sys.modules['iroha_python'] = package; "
                "import iroha_python._quantity, iroha_python.numeric_v1, "
                "iroha_python.repo, iroha_python.settlement; "
                "raise SystemExit(int("
                "'iroha_python.crypto' in sys.modules or 'iroha_python.tx' in sys.modules"
                "))"
            ),
            str(package_root),
            str(norito_root),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert probe.returncode == 0, probe.stderr


def test_asset_quantity_builder_boundary_is_exact_and_canonical() -> None:
    assert _normalize_quantity(KotodamaQuantity("12.5")) == "12.5"
    assert _normalize_quantity("12.5") == "12.5"
    assert _normalize_quantity(12) == "12"
    assert _normalize_quantity(Decimal("12.500")) == "12.5"
    assert _normalize_quantity((1 << 511) - 1) == str((1 << 511) - 1)

    for alternate in ("+1", "01", "1.0", "1.2300", "1e0", "-0", "-1", " 1"):
        with pytest.raises(ValueError):
            _normalize_quantity(alternate)
    for lossy in (1.0, True, None, object()):
        with pytest.raises(TypeError):
            _normalize_quantity(lossy)  # type: ignore[arg-type]
    for out_of_domain in (Decimal("1e1000000"), Decimal("1e-1000000")):
        with pytest.raises(ValueError):
            _normalize_quantity(out_of_domain)
    with pytest.raises(ValueError, match="canonical V1 bound"):
        _normalize_quantity("1." + "0" * 10_000)
    with pytest.raises(ValueError):
        _normalize_quantity(1 << 511)


@pytest.mark.parametrize(
    "quantity",
    [1.5, True, "+1", "01", "1.0", "1.500", "1e0", "-1", " 1"],
)
def test_repo_and_settlement_quantity_builders_reject_alternate_inputs(
    quantity: object,
) -> None:
    builders = (
        RepoCashLeg("cash#is", quantity),  # type: ignore[arg-type]
        RepoCollateralLeg("bond#is", quantity),  # type: ignore[arg-type]
        SettlementLeg(
            "cash#is",
            quantity,
            "alice@is",
            "bob@is",  # type: ignore[arg-type]
        ),
    )
    for builder in builders:
        with pytest.raises((TypeError, ValueError)):
            builder.to_payload()


@pytest.mark.parametrize("quantity", ["1.0", "01", "+1", "-1", 1, 1.0, None])
def test_repo_agreement_readback_rejects_noncanonical_quantities(quantity: object) -> None:
    payload = {
        "items": [
            {
                "id": "repo-1",
                "initiator": "alice@is",
                "counterparty": "bob@is",
                "custodian": None,
                "cash_leg": {"asset_definition_id": "cash#is", "quantity": quantity},
                "cash_source": "cash#is::bob@is",
                "collateral_leg": {
                    "asset_definition_id": "bond#is",
                    "quantity": "120",
                },
                "collateral_custody_asset": "bond#is::bob@is",
                "rate_bps": 250,
                "maturity_timestamp_ms": 2_000,
                "initiated_timestamp_ms": 1_000,
                "last_margin_check_timestamp_ms": 1_000,
                "governance": {"haircut_bps": 500, "margin_frequency_secs": 3600, "allow_early_repayment": False},
                "settlement_timestamp_ms": None,
                "status": "active",
            }
        ]
    }

    with pytest.raises((TypeError, ValueError)):
        RepoAgreementRecord.from_payload(payload["items"][0])


def test_repo_agreement_readback_requires_quantity_fields() -> None:
    payload = {
        "id": "repo-1",
        "initiator": "alice@is",
        "counterparty": "bob@is",
        "custodian": None,
        "cash_leg": {"asset_definition_id": "cash#is"},
        "cash_source": "cash#is::bob@is",
        "collateral_leg": {"asset_definition_id": "bond#is", "quantity": "120"},
        "collateral_custody_asset": "bond#is::bob@is",
        "rate_bps": 250,
        "maturity_timestamp_ms": 2_000,
        "initiated_timestamp_ms": 1_000,
        "last_margin_check_timestamp_ms": 1_000,
        "governance": {"haircut_bps": 500, "margin_frequency_secs": 3600, "allow_early_repayment": False},
        "settlement_timestamp_ms": None,
        "status": "active",
    }

    with pytest.raises(KeyError, match="quantity"):
        RepoAgreementRecord.from_payload(payload)
