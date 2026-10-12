"""Make the package sources and shared test fixtures importable, including in -I runs."""
import sys
from pathlib import Path

_TESTS = Path(__file__).resolve().parent
for _path in (_TESTS, _TESTS.parent / "src"):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))
