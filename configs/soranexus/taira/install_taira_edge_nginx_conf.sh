#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../../.." && pwd)"
ORIGINAL_ARGS=("$@")
ROSTER="${ROSTER:-${REPO_ROOT}/configs/soranexus/taira/validator_roster.local.toml}"
OUTPUT="${OUTPUT:-${REPO_ROOT}/dist/taira-edge/taira.sora.org.conf}"
TARGET_CONF="${TARGET_CONF:-}"
readonly NGINX_BIN="/usr/sbin/nginx"
readonly SYSTEM_OWNER_UID=0
readonly SYSTEM_OWNER_GID=0
readonly INSTALL_LOCK_BASENAME=".taira-edge-install.lock"
readonly INSTALL_LOCK_FD=9
INSTALL=0
RELOAD=0
ALIAS_ROUTES=()
BOOTSTRAP_PUBLICATION_DIR=""
REQUIRED_ALIASES=()
NGINX_TEST_DIRS=()
INSTALL_BACKUP_DIR=""
INSTALL_BACKUP_CONF=""
INSTALL_BACKUP_CONF_FINGERPRINT=""
TARGET_CONF_EXISTED=0
INSTALL_ROLLBACK_NEEDED=0
BACKED_UP_TARGET_FINGERPRINT="absent"
INSTALLED_CONF_FINGERPRINT=""
RENDERED_CONF_FINGERPRINT=""

cleanup_nginx_test_dirs() {
  local path
  for path in "${NGINX_TEST_DIRS[@]:-}"; do
    [[ -n "$path" && -e "$path" ]] && rm -rf "$path"
  done
  return 0
}

cleanup_runtime_state() {
  local exit_code=$?
  local rollback_failed=0

  if [[ ${INSTALL_ROLLBACK_NEEDED:-0} -eq 1 ]]; then
    if ! rollback_installed_conf; then
      rollback_failed=1
      exit_code=1
    fi
  fi
  cleanup_nginx_test_dirs
  if [[ -n "${INSTALL_BACKUP_DIR:-}" && -e "$INSTALL_BACKUP_DIR" ]]; then
    if [[ $rollback_failed -eq 1 ]]; then
      echo "retained rollback copy after failed restoration: $INSTALL_BACKUP_CONF" >&2
    else
      rm -rf "$INSTALL_BACKUP_DIR" || true
    fi
  fi

  exit "$exit_code"
}

trap cleanup_runtime_state EXIT

acquire_install_lock_or_reexec() {
  local lock_path="${target_dir}/${INSTALL_LOCK_BASENAME}"
  local status

  if [[ "${_TAIRA_EDGE_INSTALL_LOCKED:-0}" == "1" ]]; then
    if [[ "${_TAIRA_EDGE_INSTALL_LOCK_PATH:-}" != "$lock_path" ]]; then
      echo "invalid inherited Taira edge installation lock path" >&2
      return 1
    fi
    python3 - "$lock_path" "$INSTALL_LOCK_FD" "$SYSTEM_OWNER_UID" "$SYSTEM_OWNER_GID" <<'PY'
import fcntl
import os
import stat
import sys

path, descriptor_text, owner_text, group_text = sys.argv[1:]
descriptor = int(descriptor_text)
owner = int(owner_text)
group = int(group_text)

try:
    path_metadata = os.lstat(path)
    descriptor_metadata = os.fstat(descriptor)
except OSError as error:
    raise SystemExit(f"cannot inspect inherited Taira edge installation lock: {error}") from error

def identity(value):
    return value.st_dev, value.st_ino

if (
    not stat.S_ISREG(path_metadata.st_mode)
    or path_metadata.st_nlink != 1
    or path_metadata.st_uid != owner
    or path_metadata.st_gid != group
    or stat.S_IMODE(path_metadata.st_mode) != 0o600
    or identity(path_metadata) != identity(descriptor_metadata)
):
    raise SystemExit(f"inherited Taira edge installation lock is unsafe: {path}")

try:
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError as error:
    raise SystemExit(f"inherited Taira edge installation lock is not held: {path}") from error
PY
    return
  fi

  python3 - \
    "$target_dir" \
    "$INSTALL_LOCK_BASENAME" \
    "${BASH_SOURCE[0]}" \
    "$INSTALL_LOCK_FD" \
    "$SYSTEM_OWNER_UID" \
    "$SYSTEM_OWNER_GID" \
    "${ORIGINAL_ARGS[@]}" <<'PY'
import fcntl
import os
import stat
import sys

target_dir, lock_name, script, lock_descriptor_text, owner_text, group_text, *args = sys.argv[1:]
lock_descriptor = int(lock_descriptor_text)
owner = int(owner_text)
group = int(group_text)
target_dir = os.path.abspath(target_dir)
lock_path = os.path.join(target_dir, lock_name)

directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
directory_flags |= getattr(os, "O_NOFOLLOW", 0)
try:
    before = os.lstat(target_dir)
    directory_descriptor = os.open(target_dir, directory_flags)
    opened = os.fstat(directory_descriptor)
    after = os.lstat(target_dir)
except OSError as error:
    raise SystemExit(f"cannot inspect target nginx include directory {target_dir}: {error}") from error

def directory_identity(value):
    return value.st_dev, value.st_ino, value.st_uid, value.st_gid, stat.S_IMODE(value.st_mode)

if (
    not stat.S_ISDIR(before.st_mode)
    or directory_identity(before) != directory_identity(opened)
    or directory_identity(before) != directory_identity(after)
    or before.st_uid != owner
    or before.st_gid != group
    or stat.S_IMODE(before.st_mode) & 0o022
):
    raise SystemExit(
        f"target nginx include directory must be direct, owner-controlled, and non-writable by group/other: {target_dir}"
    )

lock_flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
created = False
try:
    try:
        descriptor = os.open(lock_name, lock_flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory_descriptor)
        created = True
    except FileExistsError:
        descriptor = os.open(lock_name, lock_flags, dir_fd=directory_descriptor)
    if created:
        os.fchown(descriptor, owner, group)
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        os.fsync(directory_descriptor)
    path_metadata = os.stat(lock_name, dir_fd=directory_descriptor, follow_symlinks=False)
    descriptor_metadata = os.fstat(descriptor)
except OSError as error:
    raise SystemExit(f"cannot open Taira edge installation lock {lock_path}: {error}") from error
finally:
    os.close(directory_descriptor)

if (
    not stat.S_ISREG(path_metadata.st_mode)
    or path_metadata.st_nlink != 1
    or path_metadata.st_uid != owner
    or path_metadata.st_gid != group
    or stat.S_IMODE(path_metadata.st_mode) != 0o600
    or (path_metadata.st_dev, path_metadata.st_ino) != (descriptor_metadata.st_dev, descriptor_metadata.st_ino)
):
    os.close(descriptor)
    raise SystemExit(f"Taira edge installation lock is unsafe: {lock_path}")

try:
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError as error:
    os.close(descriptor)
    raise SystemExit(f"another Taira edge installation is already running for {target_dir}") from error

if descriptor != lock_descriptor:
    os.dup2(descriptor, lock_descriptor, inheritable=True)
    os.close(descriptor)
else:
    os.set_inheritable(descriptor, True)

environment = os.environ.copy()
environment["_TAIRA_EDGE_INSTALL_LOCKED"] = "1"
environment["_TAIRA_EDGE_INSTALL_LOCK_PATH"] = lock_path
os.execve("/bin/bash", ["bash", os.path.abspath(script), *args], environment)
PY
  status=$?
  exit "$status"
}

usage() {
  cat <<'EOF'
Usage: install_taira_edge_nginx_conf.sh [--roster PATH] [--output PATH]
                                       [--target-conf PATH]
                                       [--bootstrap-publication-dir PATH]
                                       [--soracloud-alias-route ALIAS=HOST:PORT]
                                       [--require-alias ALIAS]
                                       [--install] [--reload]

Render and optionally install/reload the shared Taira edge nginx config.

Default behavior is safe: render and validate the generated file, but do not
copy it into nginx and do not reload nginx. The validator is pinned to
/usr/sbin/nginx. Run the script as root with `--install --reload` only on the
edge host after reviewing the rendered config.

For the current Solswap indexer edge binding:
  sudo bash configs/soranexus/taira/install_taira_edge_nginx_conf.sh \
    --roster configs/soranexus/taira/validator_roster.local.toml \
    --soracloud-alias-route solswap-indexer.sora=127.0.0.1:8788 \
    --require-alias solswap-indexer.sora \
    --install --reload

The default target is /etc/nginx/conf.d/taira.conf.
--bootstrap-publication-dir selects the separately promoted public checkpoint.nrt
and network-profiles.nrt pair; it never publishes or changes those files. Do not
select or relax permissions on Kagami's owner-private preparation directory.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --roster)
      [[ $# -ge 2 ]] || {
        echo "missing value for --roster" >&2
        exit 1
      }
      ROSTER="$2"
      shift 2
      ;;
    --output)
      [[ $# -ge 2 ]] || {
        echo "missing value for --output" >&2
        exit 1
      }
      OUTPUT="$2"
      shift 2
      ;;
    --target-conf)
      [[ $# -ge 2 ]] || {
        echo "missing value for --target-conf" >&2
        exit 1
      }
      TARGET_CONF="$2"
      shift 2
      ;;
    --bootstrap-publication-dir)
      [[ $# -ge 2 && -n "$2" ]] || {
        echo "missing value for --bootstrap-publication-dir" >&2
        exit 1
      }
      [[ -z "$BOOTSTRAP_PUBLICATION_DIR" ]] || {
        echo "--bootstrap-publication-dir must be supplied only once" >&2
        exit 1
      }
      BOOTSTRAP_PUBLICATION_DIR="$2"
      shift 2
      ;;
    --soracloud-alias-route)
      [[ $# -ge 2 ]] || {
        echo "missing value for --soracloud-alias-route" >&2
        exit 1
      }
      ALIAS_ROUTES+=("$2")
      shift 2
      ;;
    --require-alias)
      [[ $# -ge 2 ]] || {
        echo "missing value for --require-alias" >&2
        exit 1
      }
      REQUIRED_ALIASES+=("$2")
      shift 2
      ;;
    --install)
      INSTALL=1
      shift
      ;;
    --reload)
      RELOAD=1
      INSTALL=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "$TARGET_CONF" ]]; then
  TARGET_CONF="/etc/nginx/conf.d/taira.conf"
fi

target_dir="$(dirname -- "$TARGET_CONF")"
if [[ $INSTALL -eq 1 ]]; then
  if [[ ! -d "$target_dir" ]]; then
    echo "target nginx include directory does not exist: $target_dir" >&2
    exit 1
  fi
  if [[ $EUID -ne $SYSTEM_OWNER_UID ]]; then
    echo "nginx config installation must run as root" >&2
    exit 1
  fi
  target_dir_logical="$(cd -L -- "$target_dir" && pwd -L)"
  target_dir_physical="$(cd -P -- "$target_dir" && pwd -P)"
  if [[ -L "$target_dir" || "$target_dir_logical" != "$target_dir_physical" ]]; then
    echo "target nginx include directory must be direct: $target_dir" >&2
    exit 1
  fi
  TARGET_CONF="${target_dir_physical}/$(basename -- "$TARGET_CONF")"
  target_dir="$target_dir_physical"
  acquire_install_lock_or_reexec
fi

if [[ ! -f "$ROSTER" ]]; then
  echo "roster not found: $ROSTER" >&2
  exit 1
fi

mkdir -p "$(dirname -- "$OUTPUT")"

render_args=(
  "${REPO_ROOT}/scripts/render_taira_edge_nginx_conf.py"
  --roster "$ROSTER"
  --output "$OUTPUT"
)
if [[ -n "$BOOTSTRAP_PUBLICATION_DIR" ]]; then
  render_args+=(--bootstrap-publication-dir "$BOOTSTRAP_PUBLICATION_DIR")
fi
if ((${#ALIAS_ROUTES[@]} > 0)); then
  for route in "${ALIAS_ROUTES[@]}"; do
    render_args+=(--soracloud-alias-route "$route")
  done
fi

python3 "${render_args[@]}"

require_in_rendered_conf() {
  local pattern="$1"
  local message="$2"
  require_unchanged_rendered_conf
  if ! grep -Eq "$pattern" "$OUTPUT"; then
    echo "rendered nginx config missing ${message}: $OUTPUT" >&2
    exit 1
  fi
  require_unchanged_rendered_conf
}

validate_rendered_nginx_conf() {
  local test_dir
  local test_conf
  local rendered_include
  local rendered_snapshot_fingerprint

  require_unchanged_rendered_conf
  test_dir="$(mktemp -d "${TMPDIR:-/tmp}/taira-edge-nginx-test.XXXXXX")"
  NGINX_TEST_DIRS+=("$test_dir")
  test_conf="${test_dir}/nginx.conf"
  rendered_include="${test_dir}/rendered.conf"

  cp "$OUTPUT" "$rendered_include"
  chmod 0600 "$rendered_include"
  require_unchanged_rendered_conf
  rendered_snapshot_fingerprint="$(stable_file_fingerprint "$rendered_include")"
  if [[ "$(fingerprint_sha256 "$rendered_snapshot_fingerprint")" != "$(fingerprint_sha256 "$RENDERED_CONF_FINGERPRINT")" ]]; then
    echo "nginx validation snapshot differs from the rendered config: $OUTPUT" >&2
    return 1
  fi
  mkdir -p \
    "${test_dir}/client_body_temp" \
    "${test_dir}/fastcgi_temp" \
    "${test_dir}/logs" \
    "${test_dir}/proxy_temp" \
    "${test_dir}/scgi_temp" \
    "${test_dir}/uwsgi_temp"

  cat >"$test_conf" <<EOF
worker_processes 1;
error_log logs/error.log;
pid logs/nginx.pid;

events {
  worker_connections 1024;
}

http {
  client_body_temp_path client_body_temp;
  fastcgi_temp_path fastcgi_temp;
  proxy_temp_path proxy_temp;
  scgi_temp_path scgi_temp;
  uwsgi_temp_path uwsgi_temp;
  include ${rendered_include};
}
EOF

  require_unchanged_nginx_binary
  "$NGINX_BIN" -t -c "$test_conf" -p "${test_dir}/"
  require_unchanged_nginx_binary
  require_unchanged_rendered_conf
  if [[ "$(stable_file_fingerprint "$rendered_include")" != "$rendered_snapshot_fingerprint" ]]; then
    echo "nginx validation snapshot changed while it was checked: $rendered_include" >&2
    return 1
  fi
}

file_link_count() {
  local path="$1"
  stat -c '%h' "$path" 2>/dev/null || stat -f '%l' "$path"
}

require_safe_target_directory() {
  local group
  local owner
  local permissions

  if [[ -L "$target_dir" || ! -d "$target_dir" ]]; then
    echo "target nginx include directory must be direct: $target_dir" >&2
    return 1
  fi
  owner="$(stat -c '%u' "$target_dir" 2>/dev/null || stat -f '%u' "$target_dir")" || return 1
  group="$(stat -c '%g' "$target_dir" 2>/dev/null || stat -f '%g' "$target_dir")" || return 1
  permissions="$(stat -c '%a' "$target_dir" 2>/dev/null || stat -f '%Lp' "$target_dir")" || return 1
  if [[ "$owner" != "$SYSTEM_OWNER_UID" || "$group" != "$SYSTEM_OWNER_GID" ]] || \
     (( (8#$permissions & 8#022) != 0 )); then
    echo "target nginx include directory must be root-owned and non-writable by group/other: $target_dir" >&2
    return 1
  fi
}

require_safe_regular_file() {
  local path="$1"
  local label="$2"
  local links

  if [[ -L "$path" || ! -f "$path" ]]; then
    echo "${label} must be one direct regular file: $path" >&2
    return 1
  fi
  links="$(file_link_count "$path")" || {
    echo "cannot inspect ${label} hard-link count: $path" >&2
    return 1
  }
  if [[ "$links" != 1 ]]; then
    echo "${label} must have exactly one hard link: $path" >&2
    return 1
  fi
}

require_safe_target_leaf() {
  if [[ -e "$TARGET_CONF" || -L "$TARGET_CONF" ]]; then
    require_safe_regular_file "$TARGET_CONF" "target nginx config"
  fi
}

stable_file_fingerprint() {
  local path="$1"

  python3 - "$path" <<'PY'
import hashlib
import os
import stat
import sys

path = sys.argv[1]
flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
try:
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise OSError("not one direct regular file")
    descriptor = os.open(path, flags)
    try:
        opened_before = os.fstat(descriptor)
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        opened_after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    after = os.lstat(path)
except OSError as error:
    raise SystemExit(f"cannot read stable direct file {path}: {error}") from error

def identity(value):
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
        value.st_uid,
        value.st_gid,
        stat.S_IMODE(value.st_mode),
        value.st_nlink,
    )

snapshot = identity(before)
if snapshot != identity(opened_before) or snapshot != identity(opened_after) or snapshot != identity(after):
    raise SystemExit(f"direct file changed while it was read: {path}")

print(":".join(str(value) for value in (*snapshot, digest.hexdigest())))
PY
}

require_unchanged_rendered_conf() {
  local current

  current="$(stable_file_fingerprint "$OUTPUT")" || return 1
  if [[ -z "$RENDERED_CONF_FINGERPRINT" || "$current" != "$RENDERED_CONF_FINGERPRINT" ]]; then
    echo "rendered nginx config changed after generation: $OUTPUT" >&2
    return 1
  fi
}

fingerprint_sha256() {
  local fingerprint="$1"
  printf '%s\n' "${fingerprint##*:}"
}

require_exact_file_metadata() {
  local path="$1"
  local label="$2"
  local expected_mode="$3"
  local group
  local owner
  local permissions

  require_safe_regular_file "$path" "$label" || return 1
  owner="$(stat -c '%u' "$path" 2>/dev/null || stat -f '%u' "$path")" || return 1
  group="$(stat -c '%g' "$path" 2>/dev/null || stat -f '%g' "$path")" || return 1
  permissions="$(stat -c '%a' "$path" 2>/dev/null || stat -f '%Lp' "$path")" || return 1
  if [[ "$owner" != "$SYSTEM_OWNER_UID" || "$group" != "$SYSTEM_OWNER_GID" ]] || \
     (( 8#$permissions != 8#$expected_mode )); then
    echo "${label} must be root-owned with mode ${expected_mode}: $path" >&2
    return 1
  fi
}

fsync_path() {
  local path="$1"
  local expected_type="$2"

  python3 - "$path" "$expected_type" <<'PY'
import os
import stat
import sys

path, expected_type = sys.argv[1:]
flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
if expected_type == "directory":
    flags |= getattr(os, "O_DIRECTORY", 0)
try:
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        expected = stat.S_ISDIR(metadata.st_mode) if expected_type == "directory" else stat.S_ISREG(metadata.st_mode)
        if not expected:
            raise OSError(f"not a direct {expected_type}")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
except OSError as error:
    raise SystemExit(f"cannot durably sync {expected_type} {path}: {error}") from error
PY
}

NGINX_BIN_FINGERPRINT=""

require_safe_nginx_binary() {
  local group
  local owner
  local permissions

  require_safe_regular_file "$NGINX_BIN" "nginx executable" || return 1
  if [[ ! -x "$NGINX_BIN" ]]; then
    echo "nginx executable is not executable: $NGINX_BIN" >&2
    return 1
  fi
  owner="$(stat -c '%u' "$NGINX_BIN" 2>/dev/null || stat -f '%u' "$NGINX_BIN")" || return 1
  group="$(stat -c '%g' "$NGINX_BIN" 2>/dev/null || stat -f '%g' "$NGINX_BIN")" || return 1
  permissions="$(stat -c '%a' "$NGINX_BIN" 2>/dev/null || stat -f '%Lp' "$NGINX_BIN")" || return 1
  if [[ "$owner" != "$SYSTEM_OWNER_UID" || "$group" != "$SYSTEM_OWNER_GID" ]] || \
     (( (8#$permissions & 8#022) != 0 )); then
    echo "nginx executable must be root-owned and non-writable by group/other: $NGINX_BIN" >&2
    return 1
  fi
  NGINX_BIN_FINGERPRINT="$(stable_file_fingerprint "$NGINX_BIN")"
}

require_unchanged_nginx_binary() {
  local current

  current="$(stable_file_fingerprint "$NGINX_BIN")" || return 1
  if [[ "$current" != "$NGINX_BIN_FINGERPRINT" ]]; then
    echo "nginx executable changed during deployment: $NGINX_BIN" >&2
    return 1
  fi
}

require_expected_target_state() {
  local expected="$1"
  local current

  if [[ "$expected" == "absent" ]]; then
    if [[ -e "$TARGET_CONF" || -L "$TARGET_CONF" ]]; then
      echo "target nginx config appeared before atomic publication: $TARGET_CONF" >&2
      return 1
    fi
    return 0
  fi
  if [[ -z "$expected" ]]; then
    require_safe_target_leaf
    return
  fi
  current="$(stable_file_fingerprint "$TARGET_CONF")" || return 1
  if [[ "$current" != "$expected" ]]; then
    echo "target nginx config changed before atomic publication: $TARGET_CONF" >&2
    return 1
  fi
}

copy_to_target_conf() {
  local source_path="$1"
  local expected_target="${2:-}"
  local expected_source="${3:-}"
  local candidate=""
  local candidate_fingerprint
  local source_after
  local source_before
  local target_fingerprint

  require_safe_regular_file "$source_path" "nginx config source" || return 1
  source_before="$(stable_file_fingerprint "$source_path")" || return 1
  if [[ -n "$expected_source" && "$source_before" != "$expected_source" ]]; then
    echo "nginx config source differs from its validated identity: $source_path" >&2
    return 1
  fi
  require_expected_target_state "$expected_target" || return 1

  candidate="$(mktemp "${target_dir}/.taira-edge-install.XXXXXX")" || return 1
  if ! cp "$source_path" "$candidate" || \
     ! chown "${SYSTEM_OWNER_UID}:${SYSTEM_OWNER_GID}" "$candidate" || \
     ! chmod 0644 "$candidate" || \
     ! require_exact_file_metadata "$candidate" "nginx config candidate" 0644; then
    rm -f "$candidate" || true
    return 1
  fi

  source_after="$(stable_file_fingerprint "$source_path")" || {
    rm -f "$candidate" || true
    return 1
  }
  candidate_fingerprint="$(stable_file_fingerprint "$candidate")" || {
    rm -f "$candidate" || true
    return 1
  }
  if [[ "$source_before" != "$source_after" ]] || \
     [[ -n "$expected_source" && "$source_after" != "$expected_source" ]] || \
     [[ "$(fingerprint_sha256 "$source_after")" != "$(fingerprint_sha256 "$candidate_fingerprint")" ]]; then
    echo "nginx config source changed or was copied inconsistently: $source_path" >&2
    rm -f "$candidate" || true
    return 1
  fi
  if ! fsync_path "$candidate" file || ! require_expected_target_state "$expected_target"; then
    rm -f "$candidate" || true
    return 1
  fi
  if ! mv -f "$candidate" "$TARGET_CONF"; then
    rm -f "$candidate" || true
    return 1
  fi
  INSTALLED_CONF_FINGERPRINT="$candidate_fingerprint"
  fsync_path "$target_dir" directory || return 1

  require_exact_file_metadata "$TARGET_CONF" "installed nginx config" 0644 || return 1
  target_fingerprint="$(stable_file_fingerprint "$TARGET_CONF")" || return 1
  if [[ "$(fingerprint_sha256 "$target_fingerprint")" != "$(fingerprint_sha256 "$candidate_fingerprint")" ]]; then
    echo "installed nginx config content differs from the durable candidate: $TARGET_CONF" >&2
    return 1
  fi
  INSTALLED_CONF_FINGERPRINT="$target_fingerprint"
}

remove_target_conf() {
  require_expected_target_state "$INSTALLED_CONF_FINGERPRINT" || return 1
  rm -f "$TARGET_CONF"
  fsync_path "$target_dir" directory
}

backup_target_conf() {
  local backup_fingerprint
  local target_after
  local target_before

  TARGET_CONF_EXISTED=0
  INSTALL_BACKUP_CONF=""
  INSTALL_BACKUP_CONF_FINGERPRINT=""
  BACKED_UP_TARGET_FINGERPRINT="absent"

  if [[ ! -e "$TARGET_CONF" && ! -L "$TARGET_CONF" ]]; then
    return 0
  fi

  require_safe_target_leaf
  TARGET_CONF_EXISTED=1
  target_before="$(stable_file_fingerprint "$TARGET_CONF")"
  INSTALL_BACKUP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/taira-edge-nginx-install.XXXXXX")"
  INSTALL_BACKUP_CONF="${INSTALL_BACKUP_DIR}/previous.conf"
  cp "$TARGET_CONF" "$INSTALL_BACKUP_CONF"
  chmod 0600 "$INSTALL_BACKUP_CONF"
  require_safe_regular_file "$INSTALL_BACKUP_CONF" "nginx config rollback copy"
  target_after="$(stable_file_fingerprint "$TARGET_CONF")"
  backup_fingerprint="$(stable_file_fingerprint "$INSTALL_BACKUP_CONF")"
  if [[ "$target_before" != "$target_after" ]] || \
     [[ "$(fingerprint_sha256 "$target_after")" != "$(fingerprint_sha256 "$backup_fingerprint")" ]]; then
    echo "target nginx config changed or was copied inconsistently while making the rollback copy: $TARGET_CONF" >&2
    return 1
  fi
  BACKED_UP_TARGET_FINGERPRINT="$target_after"
  INSTALL_BACKUP_CONF_FINGERPRINT="$backup_fingerprint"
}

restore_target_conf() {
  require_safe_regular_file "$INSTALL_BACKUP_CONF" "nginx config rollback copy" || return 1
  copy_to_target_conf \
    "$INSTALL_BACKUP_CONF" \
    "$INSTALLED_CONF_FINGERPRINT" \
    "$INSTALL_BACKUP_CONF_FINGERPRINT"
}

require_unchanged_installed_conf() {
  local phase="$1"
  local current

  require_exact_file_metadata "$TARGET_CONF" "installed nginx config" 0644 || return 1
  current="$(stable_file_fingerprint "$TARGET_CONF")" || return 1
  if [[ "$current" != "$INSTALLED_CONF_FINGERPRINT" ]]; then
    echo "installed nginx config changed during ${phase}: $TARGET_CONF" >&2
    return 1
  fi
}

rollback_installed_conf() {
  if [[ -z "$INSTALLED_CONF_FINGERPRINT" ]]; then
    if require_expected_target_state "$BACKED_UP_TARGET_FINGERPRINT"; then
      return 0
    fi
    echo "failed install changed the target before its identity was pinned: $TARGET_CONF" >&2
    return 1
  fi
  if [[ $TARGET_CONF_EXISTED -eq 1 ]]; then
    if restore_target_conf; then
      echo "restored previous nginx config: $TARGET_CONF" >&2
    else
      echo "failed to restore previous nginx config: $TARGET_CONF" >&2
      return 1
    fi
  else
    if remove_target_conf; then
      echo "removed failed nginx config: $TARGET_CONF" >&2
    else
      echo "failed to remove failed nginx config: $TARGET_CONF" >&2
      return 1
    fi
  fi
}

require_safe_regular_file "$OUTPUT" "rendered nginx config"
RENDERED_CONF_FINGERPRINT="$(stable_file_fingerprint "$OUTPUT")"
require_in_rendered_conf 'server_name[[:space:]]+mon\.taira\.sora\.net;' 'Mon apex server block'
require_in_rendered_conf 'server_name[[:space:]]+\*\.mon\.taira\.sora\.net[[:space:]]+~\^\.\+\\\.mon\\\.taira\\\.sora\\\.net\$;' 'Mon wildcard/regex fallback'
require_in_rendered_conf 'proxy_next_upstream[[:space:]].*non_idempotent' 'shared-edge retry policy'

if ((${#REQUIRED_ALIASES[@]} > 0)); then
  for alias in "${REQUIRED_ALIASES[@]}"; do
    escaped_alias="$(printf '%s' "$alias" | sed 's/[.[\*^$()+?{}|\\]/\\&/g')"
    pretty_host="${alias}.mon.taira.sora.net"
    escaped_pretty="$(printf '%s' "$pretty_host" | sed 's/[.[\*^$()+?{}|\\]/\\&/g')"
    require_in_rendered_conf "server_name[[:space:]]+${escaped_pretty};" "exact Mon host for ${alias}"
    require_in_rendered_conf "proxy_set_header[[:space:]]+Host[[:space:]]+${escaped_alias};" "Host header pin for ${alias}"
  done
fi

if [[ -d "$target_dir" ]]; then
  backup_confs=()
  while IFS= read -r path; do
    backup_confs+=("$path")
  done < <(
    find "$target_dir" -maxdepth 1 -type f \( \
      -name '*.conf.bak' -o \
      -name '*.conf.backup' -o \
      -name '*.conf.old' -o \
      -name '*.conf.orig' -o \
      -name '*.conf.save' -o \
      -name '*.conf~' \
    \) -print | LC_ALL=C sort
  )
  if ((${#backup_confs[@]} > 0)); then
    {
      echo "refusing to continue while backup nginx conf files are in the include directory:"
      printf '  %s\n' "${backup_confs[@]}"
      echo "move them out of ${target_dir} before installing or validating this configuration."
    } >&2
    exit 1
  fi
fi

if [[ $INSTALL -eq 1 ]]; then
  require_safe_target_directory
  if [[ -e "$TARGET_CONF" || -L "$TARGET_CONF" ]]; then
    require_exact_file_metadata "$TARGET_CONF" "existing target nginx config" 0644
  fi
fi

require_safe_nginx_binary
validate_rendered_nginx_conf

if [[ $INSTALL -eq 1 ]]; then
  backup_target_conf
  INSTALL_ROLLBACK_NEEDED=1
  if ! copy_to_target_conf \
    "$OUTPUT" \
    "$BACKED_UP_TARGET_FINGERPRINT" \
    "$RENDERED_CONF_FINGERPRINT"; then
    echo "failed to install nginx config candidate: $TARGET_CONF" >&2
    exit 1
  fi
  require_unchanged_nginx_binary
  require_unchanged_installed_conf "pre-validation checks"
  if ! "$NGINX_BIN" -t; then
    echo "live nginx validation failed after installing candidate; rolling back: $TARGET_CONF" >&2
    exit 1
  fi
  require_unchanged_nginx_binary
  require_unchanged_installed_conf "live nginx validation"
  if [[ $RELOAD -eq 1 ]]; then
    require_unchanged_nginx_binary
    require_unchanged_installed_conf "pre-reload checks"
    if ! "$NGINX_BIN" -s reload; then
      echo "nginx reload failed after installing candidate; rolling back: $TARGET_CONF" >&2
      exit 1
    fi
    require_unchanged_nginx_binary
    require_unchanged_installed_conf "nginx reload"
    INSTALL_ROLLBACK_NEEDED=0
    echo "installed nginx config: $TARGET_CONF"
    echo "nginx reloaded"
  else
    INSTALL_ROLLBACK_NEEDED=0
    echo "installed nginx config: $TARGET_CONF"
  fi
else
  echo "rendered nginx config: $OUTPUT"
  echo "target nginx config: $TARGET_CONF"
  echo "dry run only; rerun with --install to copy and --reload to reload nginx"
fi
