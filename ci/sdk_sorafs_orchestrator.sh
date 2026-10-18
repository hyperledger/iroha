#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE_DIR="${REPO_ROOT}/fixtures/sorafs_orchestrator/multi_peer_parity_v1"
ARTIFACT_ROOT="${REPO_ROOT}/artifacts/sorafs_orchestrator_sdk"
TIMESTAMP="$(date -u +"%Y%m%dT%H%M%SZ")"
RUN_DIR="${ARTIFACT_ROOT}/${TIMESTAMP}"
RESULTS_TSV="${RUN_DIR}/results.tsv"
SUMMARY_PATH="${RUN_DIR}/summary.json"
MATRIX_PATH="${RUN_DIR}/matrix.md"
FIXTURE_SNAPSHOT_DIR="${RUN_DIR}/fixture"
METADATA_SNAPSHOT="${FIXTURE_SNAPSHOT_DIR}/metadata.json"
GIT_REV="$(git -C "${REPO_ROOT}" rev-parse HEAD)"
GENERATED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
SUMMARY_WRITTEN=0

if [[ ! -d "${FIXTURE_DIR}" ]]; then
  echo "[sorafs-sdk] missing orchestrator fixture directory: ${FIXTURE_DIR}" >&2
  exit 1
fi

mkdir -p "${RUN_DIR}" "${FIXTURE_SNAPSHOT_DIR}"
ln -sfn "${RUN_DIR}" "${ARTIFACT_ROOT}/latest"
SORAFS_SDK_TRUNCATE_PATH="${RESULTS_TSV}" python3 <<'PY'
import os
import pathlib
import sys

path = pathlib.Path(os.environ["SORAFS_SDK_TRUNCATE_PATH"])

def write_open_flags() -> int:
    return (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_TRUNC
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )

def sync_output_parent(path: pathlib.Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if nofollow:
        flags |= nofollow
    fd = os.open(path.parent, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def validate_sdk_path(path: pathlib.Path, label: str) -> None:
    if path.is_symlink():
        sys.exit(f"[sorafs-sdk] {label} must not be a symlink: {path}")
    for parent in (path.parent, *path.parent.parents):
        if parent.is_symlink():
            sys.exit(f"[sorafs-sdk] {label} parent must not be a symlink: {parent}")
        if parent.exists() and not parent.is_dir():
            sys.exit(f"[sorafs-sdk] {label} parent must be a directory: {parent}")

validate_sdk_path(path, "results TSV")
fd = os.open(path, write_open_flags(), 0o666)
try:
    os.fsync(fd)
finally:
    os.close(fd)
sync_output_parent(path)
PY

echo "[sorafs-sdk] writing parity artefacts to ${RUN_DIR}"

copy_fixture_file() {
  local source_file="${FIXTURE_DIR}/$1"
  local target_file="${FIXTURE_SNAPSHOT_DIR}/$1"
  SORAFS_SDK_COPY_SOURCE="${source_file}" \
  SORAFS_SDK_COPY_TARGET="${target_file}" \
  python3 <<'PY'
import os
import pathlib
import stat
import sys

source = pathlib.Path(os.environ["SORAFS_SDK_COPY_SOURCE"])
target = pathlib.Path(os.environ["SORAFS_SDK_COPY_TARGET"])

def read_open_flags() -> int:
    return os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)

def write_open_flags() -> int:
    return (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_TRUNC
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )

def validate_sdk_path(path: pathlib.Path, label: str) -> None:
    if path.is_symlink():
        sys.exit(f"[sorafs-sdk] {label} must not be a symlink: {path}")
    for parent in (path.parent, *path.parent.parents):
        if parent.is_symlink():
            sys.exit(f"[sorafs-sdk] {label} parent must not be a symlink: {parent}")
        if parent.exists() and not parent.is_dir():
            sys.exit(f"[sorafs-sdk] {label} parent must be a directory: {parent}")

def write_all(fd: int, chunk: bytes) -> None:
    view = memoryview(chunk)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("failed to write SoraFS SDK artifact")
        view = view[written:]

def sync_output_parent(path: pathlib.Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if nofollow:
        flags |= nofollow
    fd = os.open(path.parent, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def require_source(path: pathlib.Path, label: str) -> pathlib.Path:
    if not path.exists():
        sys.exit(f"[sorafs-sdk] {label} missing: {path}")
    validate_sdk_path(path, label)
    path_stat = path.lstat()
    if not stat.S_ISREG(path_stat.st_mode):
        sys.exit(f"[sorafs-sdk] {label} must be a regular file: {path}")
    if path_stat.st_size <= 0:
        sys.exit(f"[sorafs-sdk] {label} missing or empty: {path}")
    return path

source = require_source(source, "fixture source")
validate_sdk_path(target, "fixture snapshot")
target.parent.mkdir(parents=True, exist_ok=True)
validate_sdk_path(target, "fixture snapshot")

read_fd = os.open(source, read_open_flags())
write_fd = -1
try:
    write_fd = os.open(target, write_open_flags(), 0o666)
    while True:
        chunk = os.read(read_fd, 1024 * 1024)
        if not chunk:
            break
        write_all(write_fd, chunk)
    os.fsync(write_fd)
finally:
    os.close(read_fd)
    if write_fd >= 0:
        os.close(write_fd)
sync_output_parent(target)
PY
}

copy_fixture_file "metadata.json"
copy_fixture_file "plan.json"
copy_fixture_file "providers.json"
copy_fixture_file "telemetry.json"
copy_fixture_file "options.json"

write_summary() {
  if [[ "${SUMMARY_WRITTEN}" -eq 1 ]]; then
    return
  fi
  SUMMARY_WRITTEN=1
python3 - "${RESULTS_TSV}" "${METADATA_SNAPSHOT}" "${SUMMARY_PATH}" \
    "${MATRIX_PATH}" "${GIT_REV}" "${GENERATED_AT}" "${RUN_DIR}" \
    "${FIXTURE_SNAPSHOT_DIR}" <<'PY'
from __future__ import annotations

import json
import os
import sys
import stat
from pathlib import Path

(
    tsv_path,
    metadata_path,
    summary_path,
    matrix_path,
    git_rev,
    generated_at,
    run_dir,
    fixture_dir,
) = sys.argv[1:9]

tsv_path = Path(tsv_path)
metadata_path = Path(metadata_path)
summary_path = Path(summary_path)
matrix_path = Path(matrix_path)

def read_open_flags() -> int:
    return os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)

def write_open_flags() -> int:
    return (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_TRUNC
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )

def validate_sdk_path(path: Path, label: str) -> None:
    if path.is_symlink():
        raise SystemExit(f"[sorafs-sdk] {label} must not be a symlink: {path}")
    for parent in (path.parent, *path.parent.parents):
        if parent.is_symlink():
            raise SystemExit(
                f"[sorafs-sdk] {label} parent must not be a symlink: {parent}"
            )
        if parent.exists() and not parent.is_dir():
            raise SystemExit(
                f"[sorafs-sdk] {label} parent must be a directory: {parent}"
            )

def ensure_sdk_directory(path: Path, label: str) -> None:
    validate_sdk_path(path, label)
    path.mkdir(parents=True, exist_ok=True)
    validate_sdk_path(path, label)
    if not path.is_dir():
        raise SystemExit(f"[sorafs-sdk] {label} must be a directory: {path}")

def require_sdk_file(path: Path, label: str) -> Path:
    validate_sdk_path(path, label)
    try:
        path_stat = path.lstat()
    except FileNotFoundError as exc:
        raise SystemExit(f"[sorafs-sdk] {label} missing: {path}") from exc
    if not stat.S_ISREG(path_stat.st_mode):
        raise SystemExit(f"[sorafs-sdk] {label} must be a regular file: {path}")
    return path

def read_text_artifact(path: Path, label: str) -> str:
    require_sdk_file(path, label)
    fd = os.open(path, read_open_flags())
    try:
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            fd = -1
            return handle.read()
    finally:
        if fd >= 0:
            os.close(fd)

def write_all(fd: int, chunk: bytes) -> None:
    view = memoryview(chunk)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("failed to write SoraFS SDK artifact")
        view = view[written:]

def sync_output_parent(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if nofollow:
        flags |= nofollow
    fd = os.open(path.parent, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def write_text_artifact(path: Path, body: str, label: str) -> None:
    validate_sdk_path(path, label)
    ensure_sdk_directory(path.parent, f"{label} parent directory")
    validate_sdk_path(path, label)
    fd = os.open(path, write_open_flags(), 0o666)
    try:
        write_all(fd, body.encode("utf-8"))
        os.fsync(fd)
    finally:
        if fd >= 0:
            os.close(fd)
    sync_output_parent(path)

def load_results(path: Path) -> list[dict]:
    results: list[dict] = []
    if not path.exists():
        return results
    for line in read_text_artifact(path, "results TSV").splitlines():
        if not line:
            continue
        parts = line.split("\t", 4)
        if len(parts) != 5:
            continue
        sdk, label, status, duration, command = parts
        try:
            duration_value = int(duration)
        except ValueError:
            duration_value = 0
        results.append(
            {
                "sdk": sdk,
                "label": label,
                "status": status,
                "duration_seconds": duration_value,
                "command": command,
            }
        )
    return results

def load_metadata(path: Path) -> dict:
    if not path.exists():
        return {}
    return json.loads(read_text_artifact(path, "fixture metadata"))

results = load_results(tsv_path)
metadata = load_metadata(metadata_path)

summary: dict[str, object] = {
    "generated_at": generated_at,
    "git_rev": git_rev,
    "artifact_dir": run_dir,
    "fixture_snapshot_dir": fixture_dir,
    "matrix_path": matrix_path,
    "results": results,
    "success": bool(results) and all(entry["status"] == "passed" for entry in results),
}

if metadata:
    summary["fixture"] = {
        "path": str(metadata_path),
        "name": metadata.get("fixture"),
        "version": metadata.get("version"),
        "profile_handle": metadata.get("profile_handle"),
        "provider_count": metadata.get("provider_count"),
        "chunk_count": metadata.get("chunk_count"),
        "payload_bytes": metadata.get("payload_bytes"),
        "timestamp_hint": metadata.get("now_unix_secs"),
    }

write_text_artifact(
    summary_path,
    json.dumps(summary, indent=2) + "\n",
    "SDK parity summary",
)

matrix_lines: list[str] = []
matrix_lines.append("# SoraFS Orchestrator SDK Parity Matrix")
matrix_lines.append("")
matrix_lines.append(f"- Generated: {generated_at}")
matrix_lines.append(f"- Git revision: {git_rev}")
matrix_lines.append(f"- Artifact directory: {run_dir}")
if metadata:
    fixture_name = metadata.get("fixture") or "unknown"
    version = metadata.get("version") or "unversioned"
    payload_bytes = metadata.get("payload_bytes")
    chunk_count = metadata.get("chunk_count")
    details = f"{fixture_name} (version {version})"
    extras = []
    if chunk_count is not None:
        extras.append(f"{chunk_count} chunks")
    if payload_bytes is not None:
        extras.append(f"{payload_bytes} bytes")
    if extras:
        details = f"{details}, " + ", ".join(extras)
    matrix_lines.append(f"- Fixture: {details}")
matrix_lines.append("")
matrix_lines.append("| SDK | Check | Status | Duration (s) | Command |")
matrix_lines.append("| --- | --- | --- | ---: | --- |")
if results:
    for entry in results:
        command_for_table = entry["command"].replace("|", r"\|")
        matrix_lines.append(
            f"| {entry['sdk']} | {entry['label']} | {entry['status']} | {entry['duration_seconds']} | `{command_for_table}` |"
        )
else:
    matrix_lines.append("| (none) | — | — | — | — |")

write_text_artifact(
    matrix_path,
    "\n".join(matrix_lines) + "\n",
    "SDK parity matrix",
)

print(f"[sorafs-sdk] parity summary written to {summary_path}")
print(f"[sorafs-sdk] parity matrix written to {matrix_path}")
PY
}

trap write_summary EXIT

run_sdk_test() {
  local sdk="$1"
  shift
  local label="$1"
  shift
  local start
  start=$(date +%s)
  echo "[sorafs-sdk][${sdk}] running ${label}..."
  set +e
  "$@"
  local exit_code=$?
  set -e
  local duration status command_str
  duration=$(( $(date +%s) - start ))
  printf -v command_str '%q ' "$@"
  command_str="${command_str% }"
  if [[ "${exit_code}" -eq 0 ]]; then
    status="passed"
    echo "[sorafs-sdk][${sdk}] ${label} ok"
  else
    status="failed"
    echo "[sorafs-sdk][${sdk}] ${label} failed" >&2
  fi
  python3 - "${RESULTS_TSV}" "${sdk}" "${label}" "${status}" "${duration}" "${command_str}" <<'PY'
import os
import pathlib
import stat
import sys

path = pathlib.Path(sys.argv[1])
fields = [field.replace("\n", " ") for field in sys.argv[2:7]]

def append_open_flags() -> int:
    return (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_APPEND
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )

def validate_sdk_path(path: pathlib.Path, label: str) -> None:
    if path.is_symlink():
        raise SystemExit(f"[sorafs-sdk] {label} must not be a symlink: {path}")
    for parent in (path.parent, *path.parent.parents):
        if parent.is_symlink():
            raise SystemExit(
                f"[sorafs-sdk] {label} parent must not be a symlink: {parent}"
            )
        if parent.exists() and not parent.is_dir():
            raise SystemExit(
                f"[sorafs-sdk] {label} parent must be a directory: {parent}"
            )

def write_all(fd: int, chunk: bytes) -> None:
    view = memoryview(chunk)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("failed to write SoraFS SDK artifact")
        view = view[written:]

def sync_output_parent(path: pathlib.Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if nofollow:
        flags |= nofollow
    fd = os.open(path.parent, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

validate_sdk_path(path, "results TSV")
if path.exists() and not stat.S_ISREG(path.lstat().st_mode):
    raise SystemExit(f"[sorafs-sdk] results TSV must be a regular file: {path}")
fd = os.open(path, append_open_flags(), 0o666)
try:
    write_all(fd, ("\t".join(fields) + "\n").encode("utf-8"))
    os.fsync(fd)
finally:
    os.close(fd)
sync_output_parent(path)
PY
  return "${exit_code}"
}

run_javascript_parity() {
  local sdk_root="${REPO_ROOT}/javascript/iroha_js"
  local native_artifact="${sdk_root}/native/iroha_js_host.node"
  local native_manifest="${RUN_DIR}/node-native-abi30.json"
  local node_binary native_target

  node_binary="$(command -v node)"
  native_target="$(
    "${node_binary}" --eval \
      'process.stdout.write(`${process.platform}-${process.arch}-node${process.versions.node.split(".")[0]}`)'
  )"

  (
    native_build_target="$(
      mktemp -d "${TMPDIR:-/tmp}/iroha-sorafs-js-native-target.XXXXXX"
    )"
    trap 'rm -rf -- "${native_build_target}"' EXIT
    native_cargo="$(rustup which cargo)"
    native_rustc="$(rustup which rustc)"
    native_rustdoc="$(rustup which rustdoc)"

    # The shared Apple job envelope is not the stock JavaScript compiler envelope.
    unset RUSTC_BOOTSTRAP
    cd "${sdk_root}"
    npm ci
    "${node_binary}" --test "${REPO_ROOT}/scripts/tests/sorafs_javascript_child_contract_test.mjs" "${sdk_root}/test/sorafsNativeSuiteStructure.test.js"
    CARGO_BUILD_JOBS=1 \
      CARGO_INCREMENTAL=0 \
      CARGO_NET_OFFLINE=true \
      CARGO_TARGET_DIR="${native_build_target}" \
      IROHA_JS_CARGO_LOCKFILE_PATH="${REPO_ROOT}/Cargo.lock" \
      IROHA_JS_CARGO_PATH="${native_cargo}" \
      RUSTC="${native_rustc}" \
      RUSTDOC="${native_rustdoc}" \
      IROHA_JS_NATIVE_BUILD_PROFILE=release npm run build:native
  )
  python3 -I "${REPO_ROOT}/scripts/check_native_sdk_artifact.py" \
    record \
    --artifact "${native_artifact}" \
    --manifest "${native_manifest}" \
    --source-root "${REPO_ROOT}" \
    --node "${node_binary}" \
    --sdk node \
    --target "${native_target}"
  python3 -I "${REPO_ROOT}/scripts/check_native_sdk_artifact.py" \
    verify \
    --artifact "${native_artifact}" \
    --manifest "${native_manifest}" \
    --source-root "${REPO_ROOT}" \
    --node "${node_binary}"
  (
    cd "${sdk_root}"
    node scripts/run-test-profile.mjs sorafs-native
  )
}

run_swift_parity() {
  (
    cd "${REPO_ROOT}/IrohaSwift"
    swift test --filter SorafsOrchestratorParityTests
    swift test --filter CancelAssetLockV1Tests
    swift test --filter SorafsReferenceValidatorsTests
  )
}

run_sdk_test rust "orchestrator parity" \
  cargo test -p sorafs_orchestrator rust_orchestrator_fetch_suite_is_deterministic -- --nocapture

run_sdk_test rust "signed orderbook submission boundary" \
  cargo test -p iroha_data_model sorafs::orderbook_submission::tests -- --nocapture

run_sdk_test python "bindings parity (iroha_python_rs)" \
  cargo test -p iroha_python_rs sorafs_multi_fetch_local -- --nocapture

run_sdk_test javascript "orchestrator parity" \
  run_javascript_parity

run_sdk_test swift "orchestrator and appeal-finance parity" \
  run_swift_parity

echo "[sorafs-sdk] all orchestrator parity suites passed"
