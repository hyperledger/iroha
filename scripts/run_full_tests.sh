#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: scripts/run_full_tests.sh [options]

Runs the canonical test workflow for the Iroha workspace. By default this
builds the workspace, executes all fast tests (everything except the
integration suite), and then runs the integration tests that require a local
multi-peer network. The integration phase reuses the binaries produced by the
workspace build when available. Use the flags below to tailor the run to the
host environment.

Options:
  --only-network    Run only the integration tests (skip workspace fast tests).
  --wsl-safe        Conservative local mode for WSL and memory-constrained VMs:
                    CARGO_BUILD_JOBS=1, --test-threads=1, package-segmented
                    fast tests, CARGO_INCREMENTAL=0, serialized networks, and
                    a memory guard before each cargo step.
  --segmented-fast  Run non-integration workspace tests one package at a time.
  --fast            Run cargo via scripts/cargo_fast.sh when available.
  --fast-zero-debug When used with --fast, set CARGO_PROFILE_{DEV,TEST}_DEBUG=0.
  --no-incremental  Set CARGO_INCREMENTAL=0.
  --cargo-jobs N    Set CARGO_BUILD_JOBS for build and test compile phases.
  --test-threads N  Pass --test-threads=N to the fast and integration suites.
  --min-available-mib N
                    Refuse to start a cargo step when MemAvailable is below N.
  --resource-log PATH
                    Write memory, cgroup, disk, and top-RSS process snapshots.
  --monitor-interval-secs N
                    Snapshot resource usage every N seconds while cargo runs.
  --network-parallelism N
                    Set IROHA_TEST_NETWORK_PARALLELISM for integration tests.
  --serialize-networks
                    Set IROHA_TEST_SERIALIZE_NETWORKS=1 for one-at-a-time networks.
  --nocapture       Forward --nocapture to the integration tests for verbose logs.
  --target-dir DIR  Set CARGO_TARGET_DIR to avoid build directory lock timeouts.
  -h, --help        Show this message.

Examples:
  scripts/run_full_tests.sh
  scripts/run_full_tests.sh --wsl-safe --target-dir /tmp/iroha-wsl-tests
  scripts/run_full_tests.sh --only-network --nocapture
  scripts/run_full_tests.sh --fast --fast-zero-debug --no-incremental --only-network
EOF
}

run_fast=1
integration_args=()
target_dir=""
use_cargo_fast=false
fast_zero_debug=false
disable_incremental=false
wsl_safe=false
segmented_fast=false
cargo_jobs=""
test_threads=""
min_available_mib=""
resource_log=""
monitor_interval_secs=""
network_parallelism=""
serialize_networks=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --only-network)
            run_fast=0
            ;;
        --wsl-safe)
            wsl_safe=true
            ;;
        --fast)
            use_cargo_fast=true
            ;;
        --fast-zero-debug)
            fast_zero_debug=true
            ;;
        --no-incremental)
            disable_incremental=true
            ;;
        --segmented-fast)
            segmented_fast=true
            ;;
        --cargo-jobs)
            if [[ $# -lt 2 ]]; then
                echo "Missing argument for --cargo-jobs" >&2
                usage >&2
                exit 1
            fi
            cargo_jobs="$2"
            shift
            ;;
        --test-threads)
            if [[ $# -lt 2 ]]; then
                echo "Missing argument for --test-threads" >&2
                usage >&2
                exit 1
            fi
            test_threads="$2"
            shift
            ;;
        --min-available-mib)
            if [[ $# -lt 2 ]]; then
                echo "Missing argument for --min-available-mib" >&2
                usage >&2
                exit 1
            fi
            min_available_mib="$2"
            shift
            ;;
        --resource-log)
            if [[ $# -lt 2 ]]; then
                echo "Missing argument for --resource-log" >&2
                usage >&2
                exit 1
            fi
            resource_log="$2"
            shift
            ;;
        --monitor-interval-secs)
            if [[ $# -lt 2 ]]; then
                echo "Missing argument for --monitor-interval-secs" >&2
                usage >&2
                exit 1
            fi
            monitor_interval_secs="$2"
            shift
            ;;
        --network-parallelism)
            if [[ $# -lt 2 ]]; then
                echo "Missing argument for --network-parallelism" >&2
                usage >&2
                exit 1
            fi
            network_parallelism="$2"
            shift
            ;;
        --serialize-networks)
            serialize_networks=true
            ;;
        --nocapture)
            integration_args+=("--nocapture")
            ;;
        --target-dir)
            if [[ $# -lt 2 ]]; then
                echo "Missing argument for --target-dir" >&2
                usage >&2
                exit 1
            fi
            target_dir="$2"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            integration_args+=("$@")
            break
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
    shift
done

require_positive_int() {
    local option="$1"
    local value="$2"
    if [[ ! "${value}" =~ ^[1-9][0-9]*$ ]]; then
        echo "${option} must be a positive integer, got '${value}'" >&2
        exit 2
    fi
}

has_test_threads_arg() {
    local arg
    for arg in "$@"; do
        case "${arg}" in
            --test-threads | --test-threads=*)
                return 0
                ;;
        esac
    done
    return 1
}

if [[ "${wsl_safe}" == true ]]; then
    : "${cargo_jobs:=1}"
    : "${test_threads:=1}"
    : "${min_available_mib:=4096}"
    : "${monitor_interval_secs:=30}"
    : "${network_parallelism:=4}"
    segmented_fast=true
    disable_incremental=true
    serialize_networks=true
fi

if [[ -n "${cargo_jobs}" ]]; then
    require_positive_int "--cargo-jobs" "${cargo_jobs}"
fi
if [[ -n "${test_threads}" ]]; then
    require_positive_int "--test-threads" "${test_threads}"
fi
if [[ -n "${min_available_mib}" ]]; then
    require_positive_int "--min-available-mib" "${min_available_mib}"
fi
if [[ -n "${monitor_interval_secs}" ]]; then
    require_positive_int "--monitor-interval-secs" "${monitor_interval_secs}"
fi
if [[ -n "${network_parallelism}" ]]; then
    require_positive_int "--network-parallelism" "${network_parallelism}"
fi

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)
cd "$repo_root"
cargo_runner=(cargo)
if [[ "${use_cargo_fast}" == true ]]; then
    cargo_fast_script="${repo_root}/scripts/cargo_fast.sh"
    if [[ ! -x "${cargo_fast_script}" ]]; then
        echo "scripts/cargo_fast.sh is not available or not executable" >&2
        exit 1
    fi
    cargo_runner=("${cargo_fast_script}")
    if [[ "${fast_zero_debug}" == true ]]; then
        cargo_runner+=("--zero-debug")
    fi
    if [[ "${disable_incremental}" == true ]]; then
        cargo_runner+=("--no-incremental")
    fi
    echo "==> using scripts/cargo_fast.sh for cargo commands"
elif [[ "${fast_zero_debug}" == true ]]; then
    echo "--fast-zero-debug requires --fast" >&2
    exit 2
fi

resolve_dir() {
    local path="$1"
    local candidate
    if [[ "${path}" = /* ]]; then
        candidate="${path}"
    else
        candidate="${repo_root}/${path}"
    fi
    mkdir -p "${candidate}"
    (
        cd "${candidate}"
        pwd
    )
}

resolve_output_path() {
    local path="$1"
    local candidate
    local parent
    local name

    if [[ "${path}" = /* ]]; then
        candidate="${path}"
    else
        candidate="${repo_root}/${path}"
    fi

    parent="$(dirname "${candidate}")"
    name="$(basename "${candidate}")"
    mkdir -p "${parent}"
    (
        cd "${parent}"
        printf '%s/%s\n' "$(pwd)" "${name}"
    )
}

bin_name() {
    local raw="$1"
    case "$(uname -s)" in
        MINGW*|MSYS*|CYGWIN*)
            printf '%s.exe\n' "${raw}"
            ;;
        *)
            printf '%s\n' "${raw}"
            ;;
    esac
}

resolve_existing_binary() {
    local root="$1"
    local bin
    bin="$(bin_name "$2")"
    local candidate
    for candidate in \
        "${root}/debug/${bin}" \
        "${root}/release/${bin}"
    do
        if [[ -f "${candidate}" ]]; then
            printf '%s\n' "${candidate}"
            return 0
        fi
    done
    return 1
}

export_if_unset() {
    local name="$1"
    local value="$2"
    if [[ -z "${!name+x}" ]]; then
        export "${name}=${value}"
    fi
}

available_memory_mib() {
    if [[ -r /proc/meminfo ]]; then
        awk '/^MemAvailable:/ { print int($2 / 1024); exit }' /proc/meminfo
    fi
}

resource_snapshot() {
    local label="$1"

    if [[ -z "${resource_log}" ]]; then
        return 0
    fi

    {
        printf '===== %s %s =====\n' "$(date -Is 2>/dev/null || date)" "${label}"
        if [[ -r /proc/meminfo ]]; then
            awk '/^(MemTotal|MemFree|MemAvailable|Buffers|Cached|SwapTotal|SwapFree|Committed_AS):/ { print }' /proc/meminfo
        fi

        if [[ -r /sys/fs/cgroup/memory.current ]]; then
            printf 'cgroup.memory.current: '
            cat /sys/fs/cgroup/memory.current
        elif [[ -r /sys/fs/cgroup/memory/memory.usage_in_bytes ]]; then
            printf 'cgroup.memory.usage_in_bytes: '
            cat /sys/fs/cgroup/memory/memory.usage_in_bytes
        fi
        if [[ -r /sys/fs/cgroup/memory.max ]]; then
            printf 'cgroup.memory.max: '
            cat /sys/fs/cgroup/memory.max
        elif [[ -r /sys/fs/cgroup/memory/memory.limit_in_bytes ]]; then
            printf 'cgroup.memory.limit_in_bytes: '
            cat /sys/fs/cgroup/memory/memory.limit_in_bytes
        fi

        if [[ -n "${target_root:-}" ]]; then
            df -h "${target_root}" 2>/dev/null || true
        fi

        if ps -eo pid,ppid,rss,vsz,comm,args --sort=-rss >/dev/null 2>&1; then
            ps -eo pid,ppid,rss,vsz,comm,args --sort=-rss | head -n 21 || true
        else
            ps -axo pid,ppid,rss,vsz,comm,args 2>/dev/null | sort -nr -k3 | head -n 21 || true
        fi
        printf '\n'
    } >>"${resource_log}"
}

check_memory_available() {
    local context="$1"
    local available
    if [[ -z "${min_available_mib}" ]]; then
        return 0
    fi
    available="$(available_memory_mib)"
    if [[ -z "${available}" ]]; then
        return 0
    fi
    if (( available < min_available_mib )); then
        resource_snapshot "refusing ${context}: MemAvailable=${available} MiB below floor ${min_available_mib} MiB"
        cat >&2 <<EOF
Refusing to start ${context}: MemAvailable=${available} MiB is below the configured floor of ${min_available_mib} MiB.
Close other WSL/Windows workloads, increase WSL memory/swap, or rerun with a lower --min-available-mib if this host can safely continue.
EOF
        exit 75
    fi
}

monitor_cargo_resources() {
    local context="$1"
    local pid="$2"
    local interval_secs="$3"
    local waited

    while ps -p "${pid}" >/dev/null 2>&1; do
        resource_snapshot "during ${context} pid=${pid}"
        waited=0
        while (( waited < interval_secs )); do
            sleep 1
            if ! ps -p "${pid}" >/dev/null 2>&1; then
                return 0
            fi
            waited=$((waited + 1))
        done
    done
}

run_cargo() {
    local context
    local cargo_pid
    local monitor_pid=""
    local status

    context="cargo $*"
    check_memory_available "${context}"
    resource_snapshot "before ${context}"

    "${cargo_runner[@]}" "$@" &
    cargo_pid=$!

    if [[ -n "${resource_log}" && -n "${monitor_interval_secs}" ]]; then
        monitor_cargo_resources "${context}" "${cargo_pid}" "${monitor_interval_secs}" &
        monitor_pid=$!
    fi

    set +e
    wait "${cargo_pid}"
    status=$?
    if [[ -n "${monitor_pid}" ]]; then
        wait "${monitor_pid}" 2>/dev/null
    fi
    set -e

    resource_snapshot "after ${context} status=${status}"
    return "${status}"
}

fast_workspace_packages() {
    "${cargo_runner[@]}" metadata --locked --no-deps --format-version 1 | python3 -c '
import json
import sys

doc = json.load(sys.stdin)
packages = {package["id"]: package["name"] for package in doc["packages"]}
for member in doc["workspace_members"]:
    name = packages.get(member)
    if name and name != "integration_tests":
        print(name)
'
}

run_segmented_fast_tests() {
    local package
    local -a packages
    local -a test_features

    while IFS= read -r package; do
        packages+=("${package}")
    done < <(fast_workspace_packages)

    if ((${#packages[@]} == 0)); then
        echo "No workspace packages found for segmented fast tests" >&2
        exit 2
    fi

    echo "==> segmented fast suite: ${#packages[@]} package cargo test invocations"
    for package in "${packages[@]}"; do
        test_features=()
        if [[ "${package}" == "iroha_torii" ]]; then
            test_features=(--features iroha_torii/test-fixtures)
        fi
        if [[ -n "${test_threads}" ]]; then
            echo "==> cargo test --locked -p ${package} ${test_features[*]-} -- --test-threads=${test_threads}"
            run_cargo test --locked -p "${package}" ${test_features[@]+"${test_features[@]}"} -- --test-threads="${test_threads}"
        else
            echo "==> cargo test --locked -p ${package} ${test_features[*]-}"
            run_cargo test --locked -p "${package}" ${test_features[@]+"${test_features[@]}"}
        fi
    done
}

if [[ -n "${cargo_jobs}" ]]; then
    export CARGO_BUILD_JOBS="${cargo_jobs}"
fi
if [[ "${disable_incremental}" == true ]]; then
    export CARGO_INCREMENTAL=0
fi
if [[ "${serialize_networks}" == true ]]; then
    export IROHA_TEST_SERIALIZE_NETWORKS=1
fi
if [[ -n "${network_parallelism}" ]]; then
    export IROHA_TEST_NETWORK_PARALLELISM="${network_parallelism}"
fi

if [[ -n "${target_dir}" ]]; then
    export CARGO_TARGET_DIR="$(resolve_dir "${target_dir}")"
fi

target_root="$(resolve_dir "${CARGO_TARGET_DIR:-target}")"
export CARGO_TARGET_DIR="${target_root}"
if [[ -n "${monitor_interval_secs}" && -z "${resource_log}" ]]; then
    resource_log="${target_root}/run_full_tests_resources.log"
fi
if [[ -n "${resource_log}" ]]; then
    resource_log="$(resolve_output_path "${resource_log}")"
    : >"${resource_log}"
fi
echo "==> using CARGO_TARGET_DIR=${CARGO_TARGET_DIR}"
if [[ -n "${CARGO_BUILD_JOBS:-}" ]]; then
    echo "==> CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}"
fi
if [[ -n "${CARGO_INCREMENTAL:-}" ]]; then
    echo "==> CARGO_INCREMENTAL=${CARGO_INCREMENTAL}"
fi
if [[ -n "${test_threads}" ]]; then
    echo "==> libtest --test-threads=${test_threads}"
fi
if [[ -n "${min_available_mib}" ]]; then
    echo "==> min MemAvailable before cargo steps: ${min_available_mib} MiB"
fi
if [[ -n "${resource_log}" ]]; then
    echo "==> resource log=${resource_log}"
fi
if [[ -n "${monitor_interval_secs}" ]]; then
    echo "==> resource monitor interval=${monitor_interval_secs}s"
fi
if [[ -n "${IROHA_TEST_NETWORK_PARALLELISM:-}" ]]; then
    echo "==> IROHA_TEST_NETWORK_PARALLELISM=${IROHA_TEST_NETWORK_PARALLELISM}"
fi
if [[ -n "${IROHA_TEST_SERIALIZE_NETWORKS:-}" ]]; then
    echo "==> IROHA_TEST_SERIALIZE_NETWORKS=${IROHA_TEST_SERIALIZE_NETWORKS}"
fi

echo "==> cargo build --locked --workspace"
run_cargo build --locked --workspace

export_if_unset IROHA_TEST_SKIP_BUILD 1
export_if_unset IROHA_TEST_TARGET_DIR "${target_root}"

if irohad_bin="$(resolve_existing_binary "${target_root}" "iroha3d")"; then
    export_if_unset TEST_NETWORK_BIN_IROHAD "${irohad_bin}"
fi
if iroha_bin="$(resolve_existing_binary "${target_root}" "iroha")"; then
    export_if_unset TEST_NETWORK_BIN_IROHA "${iroha_bin}"
fi
if kagami_bin="$(resolve_existing_binary "${target_root}" "kagami")"; then
    export_if_unset KAGAMI_BIN "${kagami_bin}"
fi
if [[ -z "${IROHA_TEST_NETWORK_PERMIT_DIR+x}" ]]; then
    export IROHA_TEST_NETWORK_PERMIT_DIR="$(mktemp -d)"
fi

echo "==> integration tests configured to reuse built binaries"

if (( run_fast )); then
    if [[ "${segmented_fast}" == true ]]; then
        run_segmented_fast_tests
    elif [[ -n "${test_threads}" ]]; then
        echo "==> cargo test --locked --workspace --exclude integration_tests --features iroha_torii/test-fixtures -- --test-threads=${test_threads}"
        run_cargo test --locked --workspace --exclude integration_tests --features iroha_torii/test-fixtures -- --test-threads="${test_threads}"
    else
        echo "==> cargo test --locked --workspace --exclude integration_tests --features iroha_torii/test-fixtures"
        run_cargo test --locked --workspace --exclude integration_tests --features iroha_torii/test-fixtures
    fi
else
    echo "==> skipping fast test suite"
fi

integration_test_args=(${integration_args[@]+"${integration_args[@]}"})
if [[ -n "${test_threads}" ]] && ! has_test_threads_arg ${integration_test_args[@]+"${integration_test_args[@]}"}; then
    integration_test_args+=("--test-threads=${test_threads}")
fi

echo "==> cargo test --locked -p integration_tests ${integration_test_args[*]-}"
if ((${#integration_test_args[@]} > 0)); then
    run_cargo test --locked -p integration_tests -- "${integration_test_args[@]}"
else
    run_cargo test --locked -p integration_tests
fi

echo "==> test run completed"
