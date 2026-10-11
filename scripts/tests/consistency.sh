#!/bin/bash
set -euo pipefail

# Makes possible to set e.g. `BIN_KAGAMI=target/release/kagami` without running cargo
bin_kagami=("${BIN_KAGAMI:-cargo run --release --bin kagami --}")
bin_iroha=("${BIN_IROHA:-cargo run --release --bin iroha --}")

# Track overall success/failure
exit_code=0
update=0

if [[ "${1:-}" == "--update" ]]; then
    update=1
    shift
fi

do_check() {
    local cmd="$1"
    local target="$2"
    # Manual regeneration hint; empty when `--update` is the only reproducible route.
    local manual="${3-$cmd > $target}"
    local output_dir
    local output_name
    local staged_output

    output_dir="$(dirname "$target")"
    output_name="$(basename "$target")"
    staged_output="$(mktemp "${output_dir}/.${output_name}.XXXXXX")"

    if ! eval "$cmd" > "$staged_output"; then
        echo "[FAIL] generator command failed"
        echo "  $cmd"
        rm -f -- "$staged_output"
        exit_code=1
        return
    fi
    if [[ ! -s "$staged_output" ]]; then
        echo "[FAIL] generator produced empty output"
        echo "  $cmd"
        rm -f -- "$staged_output"
        exit_code=1
        return
    fi

    if [[ "$update" -eq 1 ]]; then
        chmod 0644 "$staged_output"
        mv -f -- "$staged_output" "$target"
        echo "[UPDATED] $target"
    else
        if ! diff "$staged_output" "$target" > /dev/null; then
            echo "[DIFF] $target is out of date"
            if [[ -n "$manual" ]]; then
                echo "Run with \"--update\" to regenerate automatically, or run manually:"
                echo "  $manual"
            else
                echo "Run with \"--update\" to regenerate it."
            fi
            exit_code=1
        else
            echo "[OK] $target is up to date"
        fi
        rm -f -- "$staged_output"
    fi
}

check_schema() {
    local schema="specs/references/schema.json"
    local genesis="specs/references/genesis_schema.json"
    local staged_schema staged_genesis
    staged_schema="$(mktemp "specs/references/.schema.json.XXXXXX")"
    staged_genesis="$(mktemp "specs/references/.genesis_schema.json.XXXXXX")"

    # One canonical invocation emits both descriptor maps. Validate both
    # outputs before replacing either checked-in artifact.
    if ! eval "$cmd_schema --genesis-out \"$staged_genesis\"" > "$staged_schema"; then
        echo "[FAIL] schema generator command failed"
        rm -f -- "$staged_schema" "$staged_genesis"
        exit_code=1
        return
    fi
    if [[ ! -s "$staged_schema" || ! -s "$staged_genesis" ]]; then
        echo "[FAIL] schema generator produced an empty output"
        rm -f -- "$staged_schema" "$staged_genesis"
        exit_code=1
        return
    fi

    if [[ "$update" -eq 1 ]]; then
        chmod 0644 "$staged_schema" "$staged_genesis"
        mv -f -- "$staged_schema" "$schema"
        mv -f -- "$staged_genesis" "$genesis"
        echo "[UPDATED] $schema"
        echo "[UPDATED] $genesis"
    else
        for pair in "$staged_schema:$schema" "$staged_genesis:$genesis"; do
            local staged="${pair%%:*}" target="${pair#*:}"
            if diff "$staged" "$target" > /dev/null; then
                echo "[OK] $target is up to date"
            else
                echo "[DIFF] $target is out of date"
                exit_code=1
            fi
        done
        rm -f -- "$staged_schema" "$staged_genesis"
    fi
}

do_render_check() {
    local cmd="$1"
    if ! eval "$cmd" > /dev/null; then
        echo "[FAIL] unable to render live CLI help"
        echo "  $cmd"
        exit_code=1
    else
        echo "[OK] live CLI help renders successfully"
    fi
}

check_genesis_template() {
    local target="defaults/genesis.template.json"

    if ! python3 - "$target" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
with path.open(encoding="utf-8") as source:
    value = json.load(source)
if not isinstance(value, dict):
    raise SystemExit("genesis source template must be a JSON object")
if "kagemusha_mint_finality" in value:
    raise SystemExit("genesis source template must not contain operator authority")
if value.get("consensus_fingerprint", object()) is not None:
    raise SystemExit("genesis source template must leave consensus_fingerprint null")
PY
    then
        echo "[FAIL] $target is not a canonical incomplete genesis source template"
        exit_code=1
        return
    fi
    echo "[OK] $target is a canonical incomplete genesis source template"
}

# Deterministic development committee shared by every checked-in Compose snapshot.
compose_seed="Iroha"
compose_peers=4
compose_dev_root=""

remove_compose_dev_root() {
    if [[ -n "$compose_dev_root" ]]; then
        rm -rf -- "$compose_dev_root"
        compose_dev_root=""
    fi
}

# `kagami docker --seed` reads a complete `genesis.json` from `--config-dir`. Complete manifests
# carry the exact signed consensus context and are never checked in, so the
# snapshots render against a disposable localnet bundle derived from the same development seed.
# The manifest only selects the consensus mode: the Compose bytes depend on the seed, peer count,
# image, build context and output path, never on this temporary directory.
prepare_compose_dev_bundle() {
    local tmp_root="${TMPDIR:-/tmp}"
    compose_dev_root="$(mktemp -d "${tmp_root%/}/iroha-compose-dev.XXXXXX")"
    trap 'remove_compose_dev_root' EXIT
    local cmd="${bin_kagami[*]} localnet generate --peers $compose_peers --seed $compose_seed --out-dir \"$compose_dev_root/localnet\""
    if ! eval "$cmd" > "$compose_dev_root/localnet.log" 2>&1; then
        echo "[FAIL] unable to render the deterministic development genesis input"
        echo "  $cmd"
        cat -- "$compose_dev_root/localnet.log"
        exit_code=1
        return 1
    fi
    if [[ ! -s "$compose_dev_root/localnet/genesis.json" ]]; then
        echo "[FAIL] the development genesis input lacks genesis.json"
        echo "  $cmd"
        exit_code=1
        return 1
    fi
}

do_check_swarm() {
    local image="$1"
    local extra="$2"
    local target="$3"
    local cmd_base="${bin_kagami[*]} docker --peers $compose_peers --seed $compose_seed --healthcheck --config-dir \"$compose_dev_root/localnet\" --image $image --print"
    # The rendering command names a temporary bundle, so `--update` is the only manual route.
    do_check "$cmd_base --out-file $target $extra" "$target" ""
}

cmd_schema="${bin_kagami[@]} advanced schema"
cmd_iroha_help="${bin_iroha[@]} tools markdown-help"
cmd_kagami_help="${bin_kagami[@]} advanced markdown-help"

tasks=()

case "${1:-}" in
    "all")
        tasks=(genesis-template schema cli-help docker-compose)
        ;;
    "genesis-template"|"schema"|"cli-help"|"docker-compose")
        tasks=("$1")
        ;;
    *)
        echo "Usage: $0 [--update] {all|genesis-template|schema|cli-help|docker-compose}"
        exit 2
        ;;
esac

for task in "${tasks[@]}"; do
    case "$task" in
        "genesis-template")
            check_genesis_template
            ;;
        "schema")
            check_schema
            ;;
        "cli-help")
            do_render_check "$cmd_iroha_help"
            do_check "$cmd_kagami_help" "crates/iroha_kagami/CommandLineHelp.md"
            ;;
        "docker-compose")
            if prepare_compose_dev_bundle; then
                do_check_swarm hyperledger/iroha:local "--build ." "defaults/docker-compose.single.yml"
                do_check_swarm hyperledger/iroha:local "--build ." "defaults/docker-compose.local.yml"
                do_check_swarm hyperledger/iroha:dev "" "defaults/docker-compose.yml"
            fi
            remove_compose_dev_root
            ;;
    esac
done

exit "$exit_code"
