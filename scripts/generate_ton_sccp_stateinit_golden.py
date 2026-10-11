#!/usr/bin/env python3
"""Generate or check `fixtures/sccp/ton_stateinit_v1.json` (specs/sccp.md §5.3.1, §11).

Purpose
    Pins the canonical initial data and workchain-0 address of the SCCP v1 TON
    minter for a fixed NetworkId, consensus instance, pinned generation,
    revision and cap, together with the code cell hashes and depths of the
    minter, wallet and bucket. Taira (`RegisterRoute`) and the Rust
    `iroha_sccp::v1::ton_cell` builder must reproduce these values from code
    hashes and depths alone.

Vectors
    `n4` and `n31` pin the committees of the same names of
    `fixtures/sccp/finality_v1.json` (compressed BLS12-381 G1 keys in
    canonical order) under that fixture's NetworkId and consensus instance.
    The committee root computed here must equal the root the fixture records.

Method
    1. Build the contracts with the pinned Acton 1.2.0 (`ton_sccp_builder.py`).
    2. Parse each compiled code BoC and recompute every value independently in
       Python (cells, committee root, initial data, StateInit, child
       addresses, and the bag of cells of the initial data).
    3. Run `contracts/ton/sccp/scripts/stateinit-golden.tolk`, which computes
       the same values with the contracts' own Tolk types, and require exact
       agreement.
    4. Write the canonical JSON, or with `--check` require the committed file
       to be byte-identical.

Options
    --check     compare instead of writing (non-zero exit on any difference)
    --no-build  reuse existing `build/` outputs
    --acton / --offline  as in `ton_sccp_builder.py`

Requires Python 3.9+ and the standard library only.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ton_sccp_builder as builder  # noqa: E402

ROOT = builder.ROOT
FIXTURE = ROOT / "fixtures" / "sccp" / "ton_stateinit_v1.json"
SCRIPT = "scripts/stateinit-golden.tolk"
SCHEMA = "iroha.sccp.ton-stateinit.v1"
FINALITY_FIXTURE = "finality_v1.json"
WALLET_OWNER = int("ab" * 32, 16)


class GoldenError(RuntimeError):
    """A mismatch or malformed input."""


# `committee` names a committee of `finality_v1.json`; the pin of `n4` is the
# pin of that fixture's certificate rows.
VECTORS: Tuple[Dict[str, Any], ...] = (
    {
        "label": "n4",
        "committee": "n4",
        "route_revision": 1,
        "max_supply": 10**18,
        "generation": 7,
        "start_height": 7000,
        "until_ms": 1_791_209_600_000,
    },
    {
        "label": "n31",
        "committee": "n31",
        "route_revision": 2,
        "max_supply": (1 << 96) - 1,
        "generation": 12,
        "start_height": 86_400,
        "until_ms": 1_801_209_600_000,
    },
)


def golden_context() -> Dict[str, Any]:
    """NetworkId, consensus instance and committee keys of the golden vectors.

    They are read from `fixtures/sccp/finality_v1.json`, so the golden pins
    the committees every other SCCP suite uses. Returns `network_id` and
    `consensus_instance` as integers and `committees`: name → (keys, root).
    """

    finality = builder.load_fixture(FINALITY_FIXTURE)
    context = finality["verification_context"]
    committees = {}
    for spec in VECTORS:
        committee = finality["committees"][spec["committee"]]
        keys = [bytes.fromhex(key[2:]) for key in committee["keys"]]
        root = builder.committee_root(keys)
        if root != int(committee["root"], 16):
            raise GoldenError(f"committee {spec['committee']}: root differs from {FINALITY_FIXTURE}")
        committees[spec["committee"]] = (keys, root)
    return {
        "network_id": int(context["taira_network_id"], 16),
        "consensus_instance": int(context["consensus_instance"], 16),
        "committees": committees,
    }


def _hex(value: bytes) -> str:
    return value.hex()


def _cell_record(cell: builder.Cell, refs: Sequence[str]) -> Dict[str, Any]:
    return {
        "bit_len": len(cell.bits),
        "data": cell.data_hex(),
        "hash": _hex(cell.hash),
        "depth": cell.depth,
        "refs": list(refs),
    }


def wallet_address(owner: int, minter: int, wallet_code: builder.Cell) -> int:
    """Account id of the wallet of `0:owner` under minter `0:minter`."""

    data = builder.Builder().coins(0).address(0, owner).address(0, minter).end()
    return int.from_bytes(builder.state_init(wallet_code, data).hash, "big")


def bucket_initial_data(minter: int, index: int) -> builder.Cell:
    """Canonical data of bucket `index`: `bucket_data` with `activated = false` and clear flags."""

    return builder.Builder().address(0, minter).uint(index, 64).bit(False).uint(0, 256).uint(0, 256).end()


def bucket_address(minter: int, index: int, bucket_code: builder.Cell) -> int:
    """Account id of bucket `index` (not activated, flags clear) under minter `0:minter`."""

    data = bucket_initial_data(minter, index)
    return int.from_bytes(builder.state_init(bucket_code, data).hash, "big")


def compute(project: Path = builder.PROJECT) -> Dict[str, Any]:
    """Recomputes the fixture from the compiled code."""

    code = {
        "minter": builder.load_compiled_code("SccpTairaXorMinter", project),
        "wallet": builder.load_compiled_code("SccpTairaXorWallet", project),
        "bucket": builder.load_compiled_code("SccpConsumedBucket", project),
    }
    code_records = {}
    for name, cell in code.items():
        cells, bits = builder.cell_tree_size(cell)
        code_records[name] = {"hash": _hex(cell.hash), "depth": cell.depth, "cells": cells, "bits": bits}
    context = golden_context()
    vectors = []
    for spec in VECTORS:
        keys, committee_root = context["committees"][spec["committee"]]
        n = len(keys)
        cells = builder.minter_initial_data(
            context["network_id"],
            context["consensus_instance"],
            spec["route_revision"],
            spec["max_supply"],
            spec["generation"],
            spec["start_height"],
            spec["until_ms"],
            keys,
            code["wallet"],
            code["bucket"],
        )
        key_cells: List[builder.Cell] = []
        chunk: Optional[builder.Cell] = cells["keys"]
        while chunk is not None:
            key_cells.append(chunk)
            chunk = chunk.refs[0] if chunk.refs else None
        root = cells["root"]
        boc = builder.serialize_boc(root)
        if builder.parse_boc(boc).hash != root.hash:
            raise GoldenError(f"{spec['label']}: the initial data does not survive its bag of cells")
        state_init = builder.state_init(code["minter"], root)
        account = int.from_bytes(state_init.hash, "big")
        vectors.append(
            {
                "label": spec["label"],
                "taira_network_id": f"{context['network_id']:064x}",
                "consensus_instance": f"{context['consensus_instance']:064x}",
                "route_revision": spec["route_revision"],
                "max_supply": str(spec["max_supply"]),
                "pin": {
                    "generation": spec["generation"],
                    "committee_root": f"{committee_root:064x}",
                    "start_height": spec["start_height"],
                    "until_ms": spec["until_ms"],
                },
                "committee": spec["committee"],
                "n": n,
                "q": builder.committee_quorum(n),
                "keys": [key.hex() for key in keys],
                "initial_data": {
                    "hash": _hex(root.hash),
                    "depth": root.depth,
                    "boc": _hex(boc),
                    "root": _cell_record(root, ["config", "committee", "checkpoints"]),
                    "config": _cell_record(cells["config"], ["initial_pin", "wallet_code", "bucket_code"]),
                    "initial_pin": _cell_record(cells["initial_pin"], []),
                    "committee": _cell_record(cells["committee"], ["keys[0]"]),
                    "checkpoints": _cell_record(cells["checkpoints"], []),
                    "keys": [
                        _cell_record(cell, [f"keys[{i + 1}]"] if cell.refs else [])
                        for i, cell in enumerate(key_cells)
                    ],
                },
                "state_init_hash": _hex(state_init.hash),
                "address": {
                    "workchain": 0,
                    "account_id": f"{account:064x}",
                    "raw": f"0:{account:064x}",
                },
                "children": {
                    "wallet_owner": f"0:{WALLET_OWNER:064x}",
                    "wallet_account_id": f"{wallet_address(WALLET_OWNER, account, code['wallet']):064x}",
                    "bucket_0_account_id": f"{bucket_address(account, 0, code['bucket']):064x}",
                    "bucket_1_account_id": f"{bucket_address(account, 1, code['bucket']):064x}",
                },
            }
        )
    return {
        "schema": SCHEMA,
        "spec": "specs/sccp.md §5.3.1 (revision 5)",
        "generator": "scripts/generate_ton_sccp_stateinit_golden.py",
        "toolchain": {"acton": builder.ACTON_VERSION, "tolk": builder.TOLK_VERSION},
        "code": code_records,
        "vectors": vectors,
    }


def parse_script_output(output: str) -> Dict[Tuple[str, str], str]:
    """Parses `sccp-stateinit <label> <key>=<value>` lines."""

    values: Dict[Tuple[str, str], str] = {}
    for line in output.splitlines():
        parts = line.strip().split()
        if len(parts) != 3 or parts[0] != "sccp-stateinit" or "=" not in parts[2]:
            continue
        key, value = parts[2].split("=", 1)
        if (parts[1], key) in values:
            raise GoldenError(f"duplicate script value {parts[1]}.{key}")
        values[(parts[1], key)] = value
    return values


def cross_check(fixture: Dict[str, Any], tolk: Dict[Tuple[str, str], str]) -> None:
    """Requires the Tolk-computed values to equal the Python ones."""

    expected: Dict[Tuple[str, str], str] = {}
    for name, record in fixture["code"].items():
        expected[("code", f"{name}_code_hash")] = record["hash"]
        expected[("code", f"{name}_code_depth")] = str(record["depth"])
    for vector in fixture["vectors"]:
        label = vector["label"]
        data = vector["initial_data"]
        expected[(label, "committee_root")] = vector["pin"]["committee_root"]
        expected[(label, "pin_hash")] = data["initial_pin"]["hash"]
        expected[(label, "config_hash")] = data["config"]["hash"]
        expected[(label, "committee_hash")] = data["committee"]["hash"]
        expected[(label, "keys_hash")] = data["keys"][0]["hash"]
        expected[(label, "checkpoints_hash")] = data["checkpoints"]["hash"]
        expected[(label, "data_hash")] = vector["initial_data"]["hash"]
        expected[(label, "data_depth")] = str(vector["initial_data"]["depth"])
        expected[(label, "state_init_hash")] = vector["state_init_hash"]
        expected[(label, "workchain")] = "0"
        expected[(label, "account_id")] = vector["address"]["account_id"]
        expected[(label, "wallet_of_abab")] = vector["children"]["wallet_account_id"]
        expected[(label, "bucket_0")] = vector["children"]["bucket_0_account_id"]
        expected[(label, "bucket_1")] = vector["children"]["bucket_1_account_id"]
    if set(tolk) != set(expected):
        raise GoldenError(f"script keys differ: {sorted(set(tolk) ^ set(expected))}")
    for key, value in expected.items():
        if tolk[key] != value:
            raise GoldenError(f"{key[0]}.{key[1]}: Tolk {tolk[key]} != Python {value}")


def render(fixture: Dict[str, Any]) -> str:
    """Canonical JSON text."""

    return json.dumps(fixture, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def run(acton: Path, check: bool, build: bool = True) -> None:
    """Builds (optionally), cross-checks and writes or checks the fixture."""

    if build:
        builder.run_acton(acton, ["build"])
    builder.check_tolk_stdlib()
    fixture = compute()
    cross_check(fixture, parse_script_output(builder.run_acton(acton, ["script", SCRIPT])))
    text = render(fixture)
    if check:
        if not FIXTURE.is_file() or FIXTURE.read_text(encoding="utf-8") != text:
            raise GoldenError(f"{FIXTURE.relative_to(ROOT)} is stale; rerun without --check")
        print(f"{FIXTURE.relative_to(ROOT)} matches the Tolk and Python StateInit computations")
        return
    FIXTURE.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE.write_text(text, encoding="utf-8")
    print(f"wrote {FIXTURE.relative_to(ROOT)}")


def main(arguments: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="compare instead of writing")
    parser.add_argument("--no-build", action="store_true", help="reuse existing build outputs")
    parser.add_argument("--acton", help="absolute Acton executable (exact pinned version)")
    parser.add_argument("--offline", action="store_true", help="never download Acton")
    parsed = parser.parse_args(arguments)
    try:
        acton = builder.resolve_acton(parsed.acton, parsed.offline)
        run(acton, check=parsed.check, build=not parsed.no_build)
        return 0
    except (GoldenError, builder.TonBuilderError) as error:
        print(f"TON SCCP StateInit golden failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
