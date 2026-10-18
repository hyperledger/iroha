#!/usr/bin/env bash
set -euo pipefail

# Purpose: Build Iroha binaries and spin up a local multi-peer network using `kagami localnet`.
# Prerequisites: Rust toolchain (cargo), curl, and this repository checked out locally.
# Environment overrides:
#   IROHA_DIR        Path to the workspace root (default: repository root).
#   CARGO_TARGET_DIR Cargo target directory override (default: <IROHA_DIR>/target).
#   KAGAMI_BIN       Path to the `kagami` binary (default: <target-dir>/<profile>/kagami).
#   IROHAD_BIN       Path to the `iroha3d` binary (default: <target-dir>/<profile>/iroha3d).
#   IROHA_BIN        Path to the `iroha` CLI binary (default: <target-dir>/<profile>/iroha).
#   SKIP_TOOL_BUILD  Skip cargo build and reuse existing binaries (default: false).
#   IROHA_LOCALNET_NOFILE_MIN Minimum RLIMIT_NOFILE for localnet peers (default: 4096).
#   IROHA_LOCALNET_KURA_BLOCKS_IN_MEMORY Override [kura].blocks_in_memory in generated peer configs.

usage() {
  cat <<'EOF'
Usage: deploy_localnet.sh [OPTIONS]

Builds `kagami`, `iroha3d`, and `iroha`, generates a fresh localnet, starts peers,
waits for readiness, and verifies the built-in KAGEMUSHA V1 asset alias.

Options:
  --iroha-dir <DIR>          Workspace root (default: repo root)
  --out-dir <DIR>            Localnet output directory (default: /tmp/iroha-localnet)
  --peers <N>                Exact Sumeragi committee: 4, 7, ..., 31 (default: 4)
  --seed <SEED>              Deterministic key seed (default: Iroha)
  --block-cadence-ms <MS>    Override the signed block cadence (ms) in generated genesis
  --consensus-mode <MODE>    Override consensus mode (permissioned or npos)
  --perf-profile <NAME>      Apply Kagami localnet perf profile (10k-permissioned or 10k-npos)
  --queue-capacity <N>       Override transaction queue capacity in peer configs
  --queue-capacity-per-user <N> Override per-user transaction queue capacity (defaults to --queue-capacity when set)
  --queue-ttl-ms <MS>        Override queue transaction_time_to_live_ms (ms)
  --kura-blocks-in-memory <N> Override number of decoded Kura blocks retained by each peer
  --logger-level <LEVEL>     Override logger.level in peer configs (e.g., warn)
  --logger-filter <SPEC>     Override logger.filter in peer configs
  --base-api-port <PORT>     Base Torii API port (default: 29080)
  --base-p2p-port <PORT>     Base P2P port (default: 33337)
  --bind-host <HOST>         Bind host (default: 127.0.0.1)
  --public-host <HOST>       Public host (default: 127.0.0.1)
  --target-dir <DIR>         Set CARGO_TARGET_DIR for builds and binary reuse
  --fast                     Run cargo via scripts/cargo_fast.sh when available
  --fast-zero-debug          With --fast, set CARGO_PROFILE_{DEV,TEST}_DEBUG=0
  --fast-no-incremental      With --fast, set CARGO_INCREMENTAL=0
  --release                  Build and run release binaries
  --no-build                 Skip cargo build and require prebuilt binaries
  --no-sample-asset          Do not include kagami's extra sample asset
  --asset-id <ID>            Built-in KAGEMUSHA V1 asset id to verify (default: 7EAD8EFYUx1aVKZPUU1fyKvr8dF1)
  --asset-name <NAME>        Built-in KAGEMUSHA V1 asset name to verify (default: usd)
  --asset-alias <ALIAS>      Built-in KAGEMUSHA V1 alias to verify (default: usd#wonderland.universal)
  --telemetry-profile <NAME> Set telemetry_profile in generated peer configs (e.g., extended)
  --timeout <SECS>           Seconds to wait for readiness (default: 30)
  --force                    Remove existing out-dir before regenerating
  -h, --help                 Show this help
EOF
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IROHA_DIR="${IROHA_DIR:-"$(cd "${SCRIPT_DIR}/.." && pwd)"}"

require_option_value() {
  local flag="$1"
  local value="${2-}"
  if [[ -z "$value" ]] || [[ "$value" == --* ]]; then
    echo "Missing value for ${flag}" >&2
    exit 2
  fi
}

resolve_dir() {
  local path="$1"
  local candidate
  if [[ "${path}" = /* ]]; then
    candidate="${path}"
  else
    candidate="${IROHA_DIR}/${path}"
  fi
  mkdir -p "${candidate}"
  (
    cd "${candidate}"
    pwd
  )
}

OUT_DIR="/tmp/iroha-localnet"
PEERS=4
SEED="Iroha"
BASE_API_PORT=29080
BASE_P2P_PORT=33337
BIND_HOST="127.0.0.1"
PUBLIC_HOST="127.0.0.1"
PROFILE="debug"
SAMPLE_ASSET=true
ASSET_ID="7EAD8EFYUx1aVKZPUU1fyKvr8dF1"
ASSET_NAME="usd"
ASSET_ALIAS="usd#wonderland.universal"
TELEMETRY_PROFILE=""
TIMEOUT_SECS=30
FORCE=false
BLOCK_CADENCE_MS=""
CONSENSUS_MODE=""
PERF_PROFILE=""
QUEUE_CAPACITY=""
QUEUE_CAPACITY_PER_USER=""
QUEUE_TTL_MS=""
LOGGER_LEVEL=""
LOGGER_FILTER=""
CURL_TIMEOUT_SECS=2
PORT_SCAN_MAX_TRIES=200
SKIP_TOOL_BUILD="${SKIP_TOOL_BUILD:-false}"
TARGET_DIR_OVERRIDE=""
USE_CARGO_FAST=false
FAST_ZERO_DEBUG=false
FAST_NO_INCREMENTAL=false
PYTHON_BIN="${PYTHON_BIN:-python3}"
KURA_BLOCKS_IN_MEMORY="${IROHA_LOCALNET_KURA_BLOCKS_IN_MEMORY:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --iroha-dir)
      IROHA_DIR="$2"
      shift 2
      ;;
    --out-dir)
      OUT_DIR="$2"
      shift 2
      ;;
    --peers)
      PEERS="$2"
      shift 2
      ;;
    --seed)
      SEED="$2"
      shift 2
      ;;
    --block-cadence-ms)
      BLOCK_CADENCE_MS="$2"
      shift 2
      ;;
    --consensus-mode)
      CONSENSUS_MODE="$2"
      shift 2
      ;;
    --perf-profile)
      PERF_PROFILE="$2"
      shift 2
      ;;
    --queue-capacity)
      QUEUE_CAPACITY="$2"
      shift 2
      ;;
    --queue-capacity-per-user)
      QUEUE_CAPACITY_PER_USER="$2"
      shift 2
      ;;
    --queue-ttl-ms)
      QUEUE_TTL_MS="$2"
      shift 2
      ;;
    --kura-blocks-in-memory)
      require_option_value "--kura-blocks-in-memory" "${2-}"
      KURA_BLOCKS_IN_MEMORY="$2"
      shift 2
      ;;
    --logger-level)
      LOGGER_LEVEL="$2"
      shift 2
      ;;
    --logger-filter)
      LOGGER_FILTER="$2"
      shift 2
      ;;
    --base-api-port)
      BASE_API_PORT="$2"
      shift 2
      ;;
    --base-p2p-port)
      BASE_P2P_PORT="$2"
      shift 2
      ;;
    --bind-host)
      BIND_HOST="$2"
      shift 2
      ;;
    --public-host)
      PUBLIC_HOST="$2"
      shift 2
      ;;
    --target-dir)
      require_option_value "--target-dir" "${2-}"
      TARGET_DIR_OVERRIDE="$2"
      shift 2
      ;;
    --fast)
      USE_CARGO_FAST=true
      shift
      ;;
    --fast-zero-debug)
      FAST_ZERO_DEBUG=true
      shift
      ;;
    --fast-no-incremental)
      FAST_NO_INCREMENTAL=true
      shift
      ;;
    --release)
      PROFILE="release"
      shift
      ;;
    --no-build|--skip-build)
      SKIP_TOOL_BUILD=true
      shift
      ;;
    --no-sample-asset)
      SAMPLE_ASSET=false
      shift
      ;;
    --asset-id)
      ASSET_ID="$2"
      shift 2
      ;;
    --asset-name)
      ASSET_NAME="$2"
      shift 2
      ;;
    --asset-alias)
      ASSET_ALIAS="$2"
      shift 2
      ;;
    --telemetry-profile)
      TELEMETRY_PROFILE="$2"
      shift 2
      ;;
    --timeout)
      TIMEOUT_SECS="$2"
      shift 2
      ;;
    --force)
      FORCE=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ ! "$PEERS" =~ ^[0-9]+$ || ${#PEERS} -gt 2 ]]; then
  echo "Invalid --peers value: $PEERS (expected an exact Sumeragi 3f + 1 committee: 4, 7, ..., 31)" >&2
  exit 2
fi
PEERS=$((10#$PEERS))
if (( PEERS < 4 || PEERS > 31 || (PEERS - 1) % 3 != 0 )); then
  echo "Invalid --peers value: $PEERS (expected an exact Sumeragi 3f + 1 committee: 4, 7, ..., 31)" >&2
  exit 2
fi

if [[ -n "$QUEUE_CAPACITY" && -z "$QUEUE_CAPACITY_PER_USER" ]]; then
  QUEUE_CAPACITY_PER_USER="$QUEUE_CAPACITY"
fi

if [[ -z "$KURA_BLOCKS_IN_MEMORY" ]]; then
  case "$PERF_PROFILE" in
    10k-*)
      # 10k localnets can commit thousands of rejected transaction results per block.
      # Keep only a small decoded hot cache; durable block bodies remain in Kura.
      KURA_BLOCKS_IN_MEMORY=32
      ;;
  esac
fi

if [[ -n "$KURA_BLOCKS_IN_MEMORY" && ! "$KURA_BLOCKS_IN_MEMORY" =~ ^[1-9][0-9]*$ ]]; then
  echo "Invalid --kura-blocks-in-memory value: $KURA_BLOCKS_IN_MEMORY (expected positive integer)" >&2
  exit 2
fi

for cmd in cargo curl; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Missing prerequisite: $cmd" >&2
    exit 1
  fi
done
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  if command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
  else
    echo "Missing prerequisite: python3 (or python)" >&2
    exit 1
  fi
fi

if [[ ! -d "$IROHA_DIR" ]]; then
  echo "IROHA_DIR does not exist: $IROHA_DIR" >&2
  exit 1
fi

cargo_runner=(cargo)
if [[ "${USE_CARGO_FAST}" == true ]]; then
  cargo_fast_script="${IROHA_DIR}/scripts/cargo_fast.sh"
  if [[ ! -x "${cargo_fast_script}" ]]; then
    echo "scripts/cargo_fast.sh is not available or not executable" >&2
    exit 2
  fi
  cargo_runner=("${cargo_fast_script}")
  if [[ "${FAST_ZERO_DEBUG}" == true ]]; then
    cargo_runner+=("--zero-debug")
  fi
  if [[ "${FAST_NO_INCREMENTAL}" == true ]]; then
    cargo_runner+=("--no-incremental")
  fi
  echo "Using scripts/cargo_fast.sh for cargo commands."
elif [[ "${FAST_ZERO_DEBUG}" == true || "${FAST_NO_INCREMENTAL}" == true ]]; then
  echo "--fast-zero-debug and --fast-no-incremental require --fast" >&2
  exit 2
fi

if [[ -n "${TARGET_DIR_OVERRIDE}" ]]; then
  export CARGO_TARGET_DIR="$(resolve_dir "${TARGET_DIR_OVERRIDE}")"
fi
TARGET_DIR="$(resolve_dir "${CARGO_TARGET_DIR:-target}")"
export CARGO_TARGET_DIR="${TARGET_DIR}"

pid_matches_localnet_peer() {
  local pid="$1"
  local config_path="$2"
  local command_line

  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  command -v ps >/dev/null 2>&1 || return 1
  command_line="$(ps -p "$pid" -o command= 2>/dev/null || true)"
  [[ -n "$command_line" ]] || return 1
  printf '%s' "$command_line" | grep -F -- "--config $config_path" >/dev/null \
    || printf '%s' "$command_line" | grep -F -- "--config=$config_path" >/dev/null
}

pid_is_running() {
  local pid="$1"

  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  command -v ps >/dev/null 2>&1 || return 0
  ps -p "$pid" -o pid= >/dev/null 2>&1
}

stop_existing_localnet() {
  local out_dir="$1"
  local out_dir_abs
  local had_live=0
  local had_error=0
  local pidfile pid peer_name config_path

  out_dir_abs="$(cd "$out_dir" 2>/dev/null && pwd || printf '%s' "$out_dir")"
  for pidfile in "$out_dir"/peer*.pid; do
    [[ -f "$pidfile" ]] || continue
    pid="$(cat "$pidfile" 2>/dev/null || true)"
    if [[ -z "$pid" ]]; then
      rm -f "$pidfile"
      continue
    fi
    if [[ ! "$pid" =~ ^[0-9]+$ ]]; then
      echo "Removing malformed pidfile $pidfile (pid=$pid)" >&2
      rm -f "$pidfile"
      continue
    fi
    if ! pid_is_running "$pid"; then
      rm -f "$pidfile"
      continue
    fi
    peer_name="$(basename "$pidfile" .pid)"
    config_path="$out_dir_abs/${peer_name}.toml"
    if ! pid_matches_localnet_peer "$pid" "$config_path"; then
      echo "Leaving $pidfile in place: live pid $pid does not match $config_path" >&2
      had_error=1
      continue
    fi
    kill "$pid" 2>/dev/null || true
    for _ in {1..20}; do
      if pid_is_running "$pid"; then
        sleep 0.25
      else
        break
      fi
    done
    if pid_is_running "$pid"; then
      echo "Refusing to remove existing out-dir while localnet peer $peer_name pid $pid is still running." >&2
      had_live=1
      continue
    fi
    rm -f "$pidfile"
  done

  if [[ "$had_live" -ne 0 || "$had_error" -ne 0 ]]; then
    return 1
  fi
}

if [[ -d "$OUT_DIR" ]]; then
  if [[ "$FORCE" == true ]]; then
    echo "Stopping existing Iroha peers in $OUT_DIR with guarded pid ownership checks..."
    stop_existing_localnet "$OUT_DIR" \
      || { echo "Out-dir $OUT_DIR still has live or mismatched pidfiles; not removing it." >&2; exit 1; }
    echo "Removing existing out-dir $OUT_DIR..."
    rm -rf "$OUT_DIR"
  else
    echo "Out-dir $OUT_DIR already exists. Re-run with --force to regenerate." >&2
    exit 1
  fi
fi

port_range_free() {
  local host="$1"
  local base="$2"
  local peers="$3"
  "$PYTHON_BIN" - "$host" "$base" "$peers" <<'PY'
import socket
import sys

host = sys.argv[1]
base = int(sys.argv[2])
peers = int(sys.argv[3])
for port in range(base, base + peers):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((host, port))
    except OSError:
        sys.exit(1)
    finally:
        sock.close()
sys.exit(0)
PY
}

find_free_port_range() {
  local host="$1"
  local base="$2"
  local peers="$3"
  local tries="$4"
  for ((i = 0; i < tries; i++)); do
    local candidate=$((base + i))
    if port_range_free "$host" "$candidate" "$peers"; then
      echo "$candidate"
      return 0
    fi
  done
  return 1
}

if ! port_range_free "$BIND_HOST" "$BASE_API_PORT" "$PEERS"; then
  new_base=$(find_free_port_range "$BIND_HOST" "$BASE_API_PORT" "$PEERS" "$PORT_SCAN_MAX_TRIES") \
    || { echo "No free API port range found near ${BASE_API_PORT} (peers=${PEERS})." >&2; exit 2; }
  echo "API port range ${BASE_API_PORT}..$((BASE_API_PORT + PEERS - 1)) in use; using ${new_base}..$((new_base + PEERS - 1))."
  BASE_API_PORT="$new_base"
fi

if ! port_range_free "$BIND_HOST" "$BASE_P2P_PORT" "$PEERS"; then
  new_base=$(find_free_port_range "$BIND_HOST" "$BASE_P2P_PORT" "$PEERS" "$PORT_SCAN_MAX_TRIES") \
    || { echo "No free P2P port range found near ${BASE_P2P_PORT} (peers=${PEERS})." >&2; exit 2; }
  echo "P2P port range ${BASE_P2P_PORT}..$((BASE_P2P_PORT + PEERS - 1)) in use; using ${new_base}..$((new_base + PEERS - 1))."
  BASE_P2P_PORT="$new_base"
fi

echo "Building Iroha tools ($PROFILE)..."
cd "$IROHA_DIR"
build_tool_bins() {
  "${cargo_runner[@]}" build "$@" \
    -p iroha_kagami --bin kagami \
    -p irohad --bin iroha3d \
    -p iroha_cli --bin iroha
}
if [[ "$SKIP_TOOL_BUILD" == "true" ]]; then
  echo "Skipping Iroha tool build; using existing binaries."
elif [[ "$PROFILE" == "release" ]]; then
  build_tool_bins --release
else
  build_tool_bins
fi

KAGAMI_BIN="${KAGAMI_BIN:-"$TARGET_DIR/$PROFILE/kagami"}"
IROHAD_BIN="${IROHAD_BIN:-"$TARGET_DIR/$PROFILE/iroha3d"}"
CLI_BIN="${IROHA_BIN:-"$TARGET_DIR/$PROFILE/iroha"}"
for bin_path in "$KAGAMI_BIN" "$IROHAD_BIN" "$CLI_BIN"; do
  if [[ ! -x "$bin_path" ]]; then
    echo "Required binary is missing or not executable: $bin_path" >&2
    exit 1
  fi
done

echo "Generating localnet in $OUT_DIR..."
KAGAMI_ARGS=(
  localnet
  --out-dir "$OUT_DIR"
  --peers "$PEERS"
  --seed "$SEED"
  --base-api-port "$BASE_API_PORT"
  --base-p2p-port "$BASE_P2P_PORT"
  --bind-host "$BIND_HOST"
  --public-host "$PUBLIC_HOST"
)
if [[ "$SAMPLE_ASSET" == true ]]; then
  KAGAMI_ARGS+=(--sample-asset)
fi
if [[ -n "$BLOCK_CADENCE_MS" ]]; then
  KAGAMI_ARGS+=(--block-cadence-ms "$BLOCK_CADENCE_MS")
fi
if [[ -n "$CONSENSUS_MODE" ]]; then
  KAGAMI_ARGS+=(--consensus-mode "$CONSENSUS_MODE")
fi
if [[ -n "$PERF_PROFILE" ]]; then
  KAGAMI_ARGS+=(--perf-profile "$PERF_PROFILE")
fi
"$KAGAMI_BIN" "${KAGAMI_ARGS[@]}"

if [[ -n "$TELEMETRY_PROFILE" ]]; then
  echo "Setting telemetry_profile=${TELEMETRY_PROFILE} in peer configs..."
  for cfg in "$OUT_DIR"/peer*.toml; do
    [[ -f "$cfg" ]] || continue
    awk -v profile="$TELEMETRY_PROFILE" '
      BEGIN { inserted = 0; replaced = 0 }
      /^[[:space:]]*telemetry_profile[[:space:]]*=/ {
        print "telemetry_profile = \"" profile "\""
        replaced = 1
        next
      }
      /^\[/ {
        if (!inserted && !replaced) {
          print "telemetry_profile = \"" profile "\""
          inserted = 1
        }
      }
      { print }
      END {
        if (!inserted && !replaced) {
          print "telemetry_profile = \"" profile "\""
        }
      }
    ' "$cfg" > "${cfg}.tmp" && mv "${cfg}.tmp" "$cfg"
  done
fi

if [[ -n "$QUEUE_CAPACITY" || -n "$QUEUE_CAPACITY_PER_USER" || -n "$QUEUE_TTL_MS" ]]; then
  echo "Applying queue overrides in peer configs..."
  for cfg in "$OUT_DIR"/peer*.toml; do
    [[ -f "$cfg" ]] || continue
    awk -v cap="$QUEUE_CAPACITY" -v cap_user="$QUEUE_CAPACITY_PER_USER" -v ttl="$QUEUE_TTL_MS" '
      function flush_queue() {
        if (!in_queue) return
        if (cap != "" && !seen_cap) print "capacity = " cap
        if (cap_user != "" && !seen_cap_user) print "capacity_per_user = " cap_user
        if (ttl != "" && !seen_ttl) print "transaction_time_to_live_ms = " ttl
      }
      function flush_torii() {
        if (!in_torii) return
        if (cap != "" && !seen_torii_threshold) print "api_high_load_tx_threshold = " cap
      }
      BEGIN {
        in_queue = 0
        in_torii = 0
        seen_cap = 0
        seen_cap_user = 0
        seen_ttl = 0
        seen_torii_threshold = 0
      }
      /^[[:space:]]*\[queue\][[:space:]]*$/ {
        flush_torii()
        in_torii = 0
        seen_torii_threshold = 0
        flush_queue()
        in_queue = 1
        seen_cap = 0
        seen_cap_user = 0
        seen_ttl = 0
        print
        next
      }
      /^[[:space:]]*\[torii\][[:space:]]*$/ {
        flush_queue()
        in_queue = 0
        flush_torii()
        in_torii = 1
        seen_torii_threshold = 0
        print
        next
      }
      /^[[:space:]]*\[/ {
        flush_queue()
        in_queue = 0
        flush_torii()
        in_torii = 0
        print
        next
      }
      {
        if (in_queue) {
          if (cap != "" && $1 == "capacity") {
            print "capacity = " cap
            seen_cap = 1
            next
          }
          if (cap_user != "" && $1 == "capacity_per_user") {
            print "capacity_per_user = " cap_user
            seen_cap_user = 1
            next
          }
          if (ttl != "" && $1 == "transaction_time_to_live_ms") {
            print "transaction_time_to_live_ms = " ttl
            seen_ttl = 1
            next
          }
        } else if (in_torii) {
          if (cap != "" && $1 == "api_high_load_tx_threshold") {
            print "api_high_load_tx_threshold = " cap
            seen_torii_threshold = 1
            next
          }
        }
        print
      }
      END {
        flush_queue()
        flush_torii()
      }
    ' "$cfg" > "${cfg}.tmp" && mv "${cfg}.tmp" "$cfg"
  done
fi

if [[ -n "$KURA_BLOCKS_IN_MEMORY" ]]; then
  echo "Applying kura.blocks_in_memory=${KURA_BLOCKS_IN_MEMORY} in peer configs..."
  for cfg in "$OUT_DIR"/peer*.toml; do
    [[ -f "$cfg" ]] || continue
    awk -v blocks="$KURA_BLOCKS_IN_MEMORY" '
      function flush_kura() {
        if (!in_kura) return
        if (!seen_blocks) print "blocks_in_memory = " blocks
      }
      BEGIN {
        in_kura = 0
        saw_kura = 0
        seen_blocks = 0
      }
      /^[[:space:]]*\[kura\][[:space:]]*$/ {
        flush_kura()
        in_kura = 1
        saw_kura = 1
        seen_blocks = 0
        print
        next
      }
      /^[[:space:]]*\[/ {
        flush_kura()
        in_kura = 0
        print
        next
      }
      {
        if (in_kura && $1 == "blocks_in_memory") {
          print "blocks_in_memory = " blocks
          seen_blocks = 1
          next
        }
        print
      }
      END {
        flush_kura()
        if (!saw_kura) {
          print ""
          print "[kura]"
          print "blocks_in_memory = " blocks
        }
      }
    ' "$cfg" > "${cfg}.tmp" && mv "${cfg}.tmp" "$cfg"
  done
fi

if [[ -n "$LOGGER_LEVEL" || -n "$LOGGER_FILTER" ]]; then
  echo "Applying logger overrides in peer configs..."
  for cfg in "$OUT_DIR"/peer*.toml; do
    [[ -f "$cfg" ]] || continue
    awk -v level="$LOGGER_LEVEL" -v filter="$LOGGER_FILTER" '
      function flush_logger() {
        if (!in_logger) return
        if (level != "" && !seen_level) print "level = \"" level "\""
        if (filter != "" && !seen_filter) print "filter = \"" filter "\""
      }
      BEGIN {
        in_logger = 0
        seen_level = 0
        seen_filter = 0
      }
      /^[[:space:]]*\[logger\][[:space:]]*$/ {
        flush_logger()
        in_logger = 1
        seen_level = 0
        seen_filter = 0
        print
        next
      }
      /^[[:space:]]*\[/ {
        flush_logger()
        in_logger = 0
        print
        next
      }
      {
        if (in_logger) {
          if (level != "" && $1 == "level") {
            print "level = \"" level "\""
            seen_level = 1
            next
          }
          if (filter != "" && $1 == "filter") {
            print "filter = \"" filter "\""
            seen_filter = 1
            next
          }
        }
        print
      }
      END {
        flush_logger()
      }
    ' "$cfg" > "${cfg}.tmp" && mv "${cfg}.tmp" "$cfg"
  done
fi

echo "Applying localnet faucet gas admission in peer configs..."
for cfg in "$OUT_DIR"/peer*.toml; do
  [[ -f "$cfg" ]] || continue
  "$PYTHON_BIN" - "$cfg" <<'PY'
import json
import os
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
lines = path.read_text().splitlines()


def extract_config_value(section_name: str, key: str) -> str | None:
    in_section = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_section = stripped.strip("[]") == section_name
            continue
        if not in_section or not stripped.startswith(f"{key} "):
            continue
        _, raw = stripped.split("=", 1)
        raw = raw.strip()
        if raw.startswith('"') and raw.endswith('"'):
            return raw[1:-1]
        return raw
    return None


asset = extract_config_value("torii.faucet", "asset_definition_id")
if not asset:
    sys.exit("could not find localnet faucet asset id")

assets = []


def add_asset(value):
    if not value:
        return
    value = value.strip().strip('"').strip("'")
    if value and value not in assets:
        assets.append(value)


for extra in re.split(r"[,\s]+", os.environ.get("IROHA_LOCALNET_EXTRA_GAS_ASSETS", "")):
    add_asset(extra)
add_asset(asset)

pipeline_start = None
for index, line in enumerate(lines):
    if line.strip() == "[pipeline.gas]":
        pipeline_start = index
        break

if pipeline_start is None:
    lines.extend(["", "[pipeline.gas]", f"accepted_assets = {json.dumps(assets)}"])
else:
    pipeline_end = len(lines)
    for index in range(pipeline_start + 1, len(lines)):
        stripped = lines[index].strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            pipeline_end = index
            break

    accepted_index = None
    for index in range(pipeline_start + 1, pipeline_end):
        if lines[index].strip().startswith("accepted_assets"):
            accepted_index = index
            break

    if accepted_index is None:
        lines.insert(pipeline_start + 1, f"accepted_assets = {json.dumps(assets)}")
    else:
        for existing in re.findall(r'"([^"]+)"', lines[accepted_index]):
            add_asset(existing)
        prefix = lines[accepted_index].split("[", 1)[0]
        lines[accepted_index] = f"{prefix}{json.dumps(assets)}"


def has_unit_table_for(candidate: str) -> bool:
    in_unit_table = False
    current_unit_has_asset = False
    for line in lines + ["[end]"]:
        stripped = line.strip()
        if stripped == "[[pipeline.gas.units_per_gas]]":
            if in_unit_table and current_unit_has_asset:
                return True
            in_unit_table = True
            current_unit_has_asset = False
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            if in_unit_table and current_unit_has_asset:
                return True
            in_unit_table = False
            current_unit_has_asset = False
            continue
        if in_unit_table:
            match = re.match(r'asset\s*=\s*"([^"]+)"', stripped)
            if match and match.group(1) == candidate:
                current_unit_has_asset = True
    return False


for candidate in assets:
    if has_unit_table_for(candidate):
        continue
    lines.extend(
        [
            "",
            "[[pipeline.gas.units_per_gas]]",
            f"asset = {json.dumps(candidate)}",
            "units_per_gas = 0",
            'twap_local_per_xor = "1"',
            'liquidity_profile = "tier1"',
            'volatility_class = "stable"',
        ]
    )

path.write_text("\n".join(lines) + "\n")
PY
done

echo "Starting Iroha peers..."
cd "$OUT_DIR"
chmod +x start.sh stop.sh
LOCALNET_NOFILE_MIN="${IROHA_LOCALNET_NOFILE_MIN:-4096}"
CURRENT_NOFILE="$(ulimit -n 2>/dev/null || echo 0)"
if [[ "$CURRENT_NOFILE" -lt "$LOCALNET_NOFILE_MIN" ]]; then
  if ulimit -n "$LOCALNET_NOFILE_MIN" 2>/dev/null; then
    echo "Raised RLIMIT_NOFILE to ${LOCALNET_NOFILE_MIN} for localnet."
  else
    echo "Warning: failed to raise RLIMIT_NOFILE (current=${CURRENT_NOFILE})." >&2
  fi
fi
if [[ -z "${RUST_LOG:-}" && "$PROFILE" == "debug" ]]; then
  export RUST_LOG="warn"
fi
IROHAD_BIN="$IROHAD_BIN" IROHA_CLI="$CLI_BIN" ./start.sh

format_host_for_url() {
  local host="$1"
  if [[ "$host" == \[*\] ]]; then
    printf '%s' "$host"
  elif [[ "$host" == *:* ]]; then
    printf '[%s]' "$host"
  else
    printf '%s' "$host"
  fi
}

PUBLIC_HOST_URL="$(format_host_for_url "$PUBLIC_HOST")"

echo "Waiting for network to be ready..."
READY=false
for ((i = 1; i <= TIMEOUT_SECS; i++)); do
  if curl -sf --connect-timeout "$CURL_TIMEOUT_SECS" --max-time "$CURL_TIMEOUT_SECS" \
    "http://$PUBLIC_HOST_URL:$BASE_API_PORT/health" >/dev/null 2>&1; then
    READY=true
    break
  fi
  sleep 1
done

if [[ "$READY" != true ]]; then
  echo "Network did not become ready after ${TIMEOUT_SECS}s." >&2
  echo "Check logs in $OUT_DIR or re-run with a longer --timeout." >&2
  exit 1
fi

echo "Network is ready:"
curl -sf --connect-timeout "$CURL_TIMEOUT_SECS" --max-time "$CURL_TIMEOUT_SECS" \
  "http://$PUBLIC_HOST_URL:$BASE_API_PORT/health" || true

# /status may be protected by operator auth depending on Torii config; it is not required for
# localnet readiness checks.
curl -s --connect-timeout "$CURL_TIMEOUT_SECS" --max-time "$CURL_TIMEOUT_SECS" \
  "http://$PUBLIC_HOST_URL:$BASE_API_PORT/status" || true

echo "Consensus readiness was established through bounded public /status; inspect the frozen mode with an operator-signed Sumeragi status request when needed."

CFG="$OUT_DIR/client.toml"
echo ""
echo "Verifying built-in KAGEMUSHA V1 alias $ASSET_ALIAS..."
asset_alias_request="$(printf '{\"alias\":\"%s\"}' "$ASSET_ALIAS")"
asset_alias_response="$(
  curl -sf --connect-timeout "$CURL_TIMEOUT_SECS" --max-time "$CURL_TIMEOUT_SECS" \
    -H "Content-Type: application/json" \
    -d "$asset_alias_request" \
    "http://$PUBLIC_HOST_URL:$BASE_API_PORT/v1/assets/aliases/resolve"
)" || {
  echo "Failed to resolve built-in KAGEMUSHA V1 alias $ASSET_ALIAS." >&2
  exit 1
}
ASSET_ALIAS_RESPONSE="$asset_alias_response" \
"$PYTHON_BIN" - "$ASSET_ID" "$ASSET_NAME" "$ASSET_ALIAS" <<'PY'
import json
import os
import sys

expected_id, expected_name, expected_alias = sys.argv[1:4]
payload = json.loads(os.environ["ASSET_ALIAS_RESPONSE"])
actual_id = payload.get("asset_definition_id")
actual_name = payload.get("asset_name")
actual_alias = payload.get("alias")
if actual_id != expected_id:
    raise SystemExit(f"expected asset_definition_id {expected_id}, got {actual_id}")
if actual_name != expected_name:
    raise SystemExit(f"expected asset_name {expected_name}, got {actual_name}")
if actual_alias != expected_alias:
    raise SystemExit(f"expected alias {expected_alias}, got {actual_alias}")
PY

echo ""
echo "Iroha localnet is running in $OUT_DIR."
echo "CLI binary: $CLI_BIN"
echo "Client config: $CFG"
echo "Built-in KAGEMUSHA V1 asset: $ASSET_NAME ($ASSET_ID) alias $ASSET_ALIAS"
echo "To stop: cd $OUT_DIR && ./stop.sh"
