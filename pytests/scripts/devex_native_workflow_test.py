"""Keep the native developer bundle gate distinct from cross-builds and local profiling."""

from pathlib import Path
import json
import platform
import re
import shutil
import subprocess
import textwrap

import pytest


WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/devex_native.yml"


def _workflow() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def _preflight() -> str:
    source = _workflow().split("          python - <<'PY'\n", 1)[1]
    return textwrap.dedent(source.split("          PY\n", 1)[0])


def test_all_five_native_targets_run_real_owners_and_installed_release_smoke():
    workflow = _workflow()
    assert set(re.findall(r"^            target: (.+)$", workflow, re.MULTILINE)) == {
        "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu",
        "x86_64-apple-darwin", "aarch64-apple-darwin", "x86_64-pc-windows-msvc",
    }
    assert "workflow_dispatch:" in workflow
    assert "cancel-in-progress: false" in workflow
    assert "persist-credentials: false" in workflow
    assert 'test "$WORKFLOW_SHA" = "$source_sha"' in workflow
    commands = " ".join(workflow.split())
    assert "cargo test --locked --release -p iroha_fs -p iroha_wallet -p iroha_deploy -p iroha_contract_deploy --lib -- --test-threads=1" in commands
    assert "cargo test --locked --release -p musubi --lib -- --test-threads=1" in commands
    assert "cargo test --locked --release -p mochi-core -p mochi-ui --features mochi-ui/gui --lib --bins" in commands
    assert "cargo run --locked --release -p xtask --features dev-tools --bin xtask -- mochi-bundle --profile release" in commands
    assert "--matrix target/devex-native/matrix.json --smoke" in commands
    assert "installed_private_root_lifecycle_and_listener_isolation -- --exact --ignored --test-threads=1" in commands
    assert "installed_parent_attachment_private_contracts_and_payload_isolation -- --exact --ignored --test-threads=1" in commands
    assert "openssl version" in commands
    assert "import ssl, sys; assert sys.version_info >= (3, 10)" in commands
    assert "--profile local-release" not in workflow
    assert not re.search(r"continue-on-error|allow_failure|cargo.*--target", workflow)
    assert all(len(pin) == 40 for pin in re.findall(r"uses: [^@\n]+@([^\s]+)", workflow))


@pytest.mark.parametrize(
    "host,machine,ram_gib,disk_gib,passes",
    [
        ("x86_64-unknown-linux-gnu", "x86_64", 32, 100, True),
        ("aarch64-unknown-linux-gnu", "x86_64", 32, 100, False),
        ("x86_64-unknown-linux-gnu", "aarch64", 32, 100, False),
        ("x86_64-unknown-linux-gnu", "x86_64", 7, 100, False),
        ("x86_64-unknown-linux-gnu", "x86_64", 32, 14, False),
    ],
)
def test_preflight_refuses_cross_host_and_insufficient_resources_before_runtime_setup(
    monkeypatch, tmp_path, host, machine, ram_gib, disk_gib, passes
):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("EXPECTED_TARGET", "x86_64-unknown-linux-gnu")
    monkeypatch.setenv("BUNDLE_HOST", "linux-x86_64")
    monkeypatch.setenv("SOURCE_SHA", "1" * 40)
    environment = tmp_path / "runner-environment"
    monkeypatch.setenv("GITHUB_ENV", str(environment))
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    monkeypatch.setattr(platform, "machine", lambda: machine)
    monkeypatch.setattr(subprocess, "check_output", lambda *a, **k: f"rustc 1.93.1\nhost: {host}\n")
    monkeypatch.setattr("os.sysconf", lambda name: 4096 if name == "SC_PAGE_SIZE" else ram_gib * 1024**3 // 4096)
    disk = type("Disk", (), {"free": disk_gib * 1024**3})()
    monkeypatch.setattr(shutil, "disk_usage", lambda _: disk)
    script = compile(_preflight(), str(WORKFLOW), "exec")
    if passes:
        exec(script, {})
        assert "IROHA_TEST_RUNTIME_DIRECTORY=" in environment.read_text(encoding="utf-8")
        assert "IROHA_DEVEX_BUNDLE_BIN=" in environment.read_text(encoding="utf-8")
    else:
        with pytest.raises(SystemExit):
            exec(script, {})
        assert not environment.exists()
    report = json.loads((tmp_path / "target/devex-native/host.json").read_text(encoding="utf-8"))
    assert report["source_sha"] == "1" * 40
    assert report["host"] == host
    assert report["profile"] == "release"
    assert report["reference_latency_qualified"] is False


@pytest.mark.parametrize("arch,machine", [("aarch64", "arm64"), ("x86_64", "x86_64")])
def test_macos_native_preflight_selects_the_only_packaged_app_runtime(
    monkeypatch, tmp_path, arch, machine
):
    monkeypatch.chdir(tmp_path)
    target = arch + "-apple-darwin"
    monkeypatch.setenv("EXPECTED_TARGET", target)
    monkeypatch.setenv("BUNDLE_HOST", "macos-" + arch)
    monkeypatch.setenv("SOURCE_SHA", "1" * 40)
    environment = tmp_path / "runner-environment"
    monkeypatch.setenv("GITHUB_ENV", str(environment))
    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    monkeypatch.setattr(platform, "machine", lambda: machine)
    monkeypatch.setattr(subprocess, "check_output", lambda args, **kwargs:
        str(32 * 1024**3) if args[0] == "sysctl" else f"rustc 1.93.1\nhost: {target}\n")
    monkeypatch.setattr(shutil, "disk_usage", lambda _: type("Disk", (), {"free": 100 * 1024**3})())
    exec(compile(_preflight(), str(WORKFLOW), "exec"), {})
    expected = (tmp_path / "target/devex-native" / ("mochi-macos-" + arch + "-release")
                / "Mochi.app/Contents/MacOS")
    assert environment.read_text(encoding="utf-8").splitlines() == [
        "IROHA_DEVEX_BUNDLE_BIN=" + str(expected),
        "IROHA_TEST_RUNTIME_DIRECTORY=" + str(expected),
    ]
