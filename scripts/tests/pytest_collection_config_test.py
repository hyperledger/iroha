"""Exercise distinct script-test identities and suite-owned helper imports."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT_SUITES = ("scripts/tests", "pytests/scripts")


def _fixture(root: Path) -> None:
    """Copy the maintained collectors and seed matching test file basenames."""
    for relative, helper, module in (
        ("scripts/tests", "_script_owned_helper", "scripts.tests"),
        ("pytests/scripts", "_pytest_owned_helper", "pytests.scripts"),
    ):
        directory = root / relative
        directory.mkdir(parents=True)
        shutil.copyfile(ROOT / relative / "conftest.py", directory / "conftest.py")
        (directory / f"{helper}.py").write_text(
            "from pathlib import Path\nLOCATION = Path(__file__).resolve().parent\n",
            encoding="utf-8",
        )
        (directory / "same_name_test.py").write_text(
            f"from {helper} import LOCATION\n"
            "from pathlib import Path\n"
            "def test_module_identity_and_owned_helper():\n"
            f"    assert __name__ == {module + '.same_name_test'!r}\n"
            "    assert LOCATION == Path(__file__).resolve().parent\n",
            encoding="utf-8",
        )


def _pytest(root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    """Run a genuine hermetic pytest child using the selected interpreter."""
    environment = os.environ.copy()
    environment.pop("PYTEST_ADDOPTS", None)
    environment.pop("PYTHONPATH", None)
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", *arguments],
        cwd=root,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )


@pytest.mark.parametrize("selection", [
    SCRIPT_SUITES,
    tuple(reversed(SCRIPT_SUITES)),
    (SCRIPT_SUITES[0],),
    (SCRIPT_SUITES[1],),
])
def test_maintained_collection_preserves_duplicate_names_and_owned_helpers(
    tmp_path: Path, selection: tuple[str, ...],
) -> None:
    _fixture(tmp_path)
    # The unconfigured collector actually rejects the same duplicate files.
    original = _pytest(tmp_path, "--collect-only", *SCRIPT_SUITES)
    assert original.returncode == 2, original.stdout
    assert "import file mismatch" in original.stdout

    shutil.copyfile(ROOT / "pytest.ini", tmp_path / "pytest.ini")
    result = _pytest(tmp_path, *selection)
    assert result.returncode == 0, result.stdout
    assert f"{len(selection)} passed" in result.stdout
