"""Canonical script imports and this suite's explicitly owned helper directory."""

from pathlib import Path
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [
    str(REPOSITORY_ROOT),
    str(REPOSITORY_ROOT / "scripts"),
    str(Path(__file__).resolve().parent),
]
