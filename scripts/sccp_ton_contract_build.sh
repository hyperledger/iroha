#!/bin/sh
# Builds and checks the SCCP v1 TON contracts (contracts/ton/sccp, specs/sccp.md
# revision 5, §5.3) with the pinned native Acton 1.2.0 / Tolk 1.4.2 toolchain
# (specs/sccp.md §5.5). Prerequisite: python3 (3.9 or later) on PATH.
#
# Without a command it runs `all`: the freshness check of the three Tolk vector
# files generated from the fixtures under fixtures/sccp/, `acton fmt --check`,
# `acton build` (with the Tolk stdlib version check), the wrapper freshness
# check, the Acton emulator suite `tests/unit` with its gas report
# (contracts/ton/sccp/gas-current.json, compared with gas-baseline.json at
# 1.1 x, specs/sccp.md §5.4), and the StateInit golden check of
# fixtures/sccp/ton_stateinit_v1.json. On first use the pinned Acton release
# archive is downloaded and verified by SHA-256 (see
# scripts/ton_sccp_builder.py); `--offline` forbids that download and uses the
# cache under contracts/ton/sccp/.toolchain. No Docker or Rosetta is involved.
#
# Usage: scripts/sccp_ton_contract_build.sh [--acton /abs/acton] [--offline] [command ...]
#   see `python3 scripts/ton_sccp_builder.py --help` for the commands.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$script_dir/ton_sccp_builder.py" "$@"
