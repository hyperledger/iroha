"""Canonical script-test imports and explicit external verifier selection."""

from __future__ import annotations

from pathlib import Path
import sys

import pytest


# Executable script modules use their scripts directory for sibling imports.
# Establish the canonical roots and this suite's owned helper directory before
# pytest imports test modules, independently of collection order. Importlib
# collection gives test modules distinct names across the two script suites.
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [
    str(REPOSITORY_ROOT),
    str(REPOSITORY_ROOT / "scripts"),
    str(Path(__file__).resolve().parent),
]


def pytest_addoption(parser: pytest.Parser) -> None:
    """Register independently supplied cosign executable and exact-byte trust pin."""

    group = parser.getgroup("sorafs-cosign", "SoraFS external cosign qualification")
    group.addoption(
        "--sorafs-cosign-verifier",
        action="store",
        default=None,
        help="Explicit cosign executable path; never discovered from PATH.",
    )
    group.addoption(
        "--sorafs-cosign-verifier-sha256",
        action="store",
        default=None,
        help="Independently reviewed lowercase SHA-256 of that exact executable.",
    )
