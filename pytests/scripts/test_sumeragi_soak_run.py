"""End-to-end run of the soak orchestrator (``scripts/sumeragi_soak.py``) over fake binaries.

A fake ``kagami localnet generate`` writes peer configs, a client config and a start script; a fake
``iroha3d`` serves ``/health`` and ``/status`` on its Torii port and logs the driver's audit
lines (JSON) for a deterministic chain whose height survives restarts; a fake ``iroha`` CLI
answers ping batches and probes. The run exercises everything but consensus itself: config
patching (JSON logger with the audit filter, P2P addresses at the proxies), process starts,
``kill -9`` and restarts with per-boot logs, proxy link conditions, the load generator, the
timeline and the verdict.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import os
import random
import stat
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 uses the pinned backport (scripts/requirements.txt).
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "sumeragi_soak.py"
SPEC = importlib.util.spec_from_file_location("sumeragi_soak_run_under_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
soak = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = soak
SPEC.loader.exec_module(soak)

FAKE_KAGAMI = r'''
import argparse, os, sys
from pathlib import Path
parser = argparse.ArgumentParser()
parser.add_argument("command")
parser.add_argument("action")
parser.add_argument("--peers", type=int)
parser.add_argument("--seed")
parser.add_argument("--base-api-port", type=int)
parser.add_argument("--base-p2p-port", type=int)
parser.add_argument("--out-dir", type=Path)
args = parser.parse_args()
assert args.command == "localnet"
assert args.action == "generate"
out = args.out_dir
out.mkdir(parents=True)
def crc(body):
    value = 0xFFFF
    for byte in ("addr:" + body).encode():
        value ^= byte << 8
        for _ in range(8):
            value = ((value << 1) ^ 0x1021) & 0xFFFF if value & 0x8000 else (value << 1) & 0xFFFF
    return f"{value:04X}"
def literal(host, port):
    return f"addr:{host}:{port}#{crc(f'{host}:{port}')}"
trusted = ", ".join(f'"k{j}@{literal("127.0.0.1", args.base_p2p_port + j)}"' for j in range(args.peers))
for i in range(args.peers):
    (out / "storage" / f"peer{i}").mkdir(parents=True)
    (out / "state" / f"peer{i}").mkdir(parents=True)
    (out / f"peer{i}.toml").write_text(f"""chain = "soak-test"
trusted_peers = [{trusted}]

[network]
address = "{literal("0.0.0.0", args.base_p2p_port + i)}"
public_address = "{literal("127.0.0.1", args.base_p2p_port + i)}"

[kura]
store_dir = "{out}/storage/peer{i}"

[sumeragi]
records_dir = "{out}/state/peer{i}/sumeragi-records"

[logger]
format = "compact"
level = "info"

[torii]
address = "127.0.0.1:{args.base_api_port + i}"

[torii.faucet]
asset_definition_id = "FAKEXOR"
""")
for name in filter(None, os.environ.get("SOAK_TEST_FAIL_FIRST_BOOT", "").split(",")):
    (out / f"{name}.fail-once").write_text("exit at the first boot\n")
(out / "genesis.expected_hash").write_text("fake-network-id\n")
(out / "genesis.public_key").write_text("ed0120GENESIS\n")
(out / "genesis.private_key").write_text("802620GENESISSECRET\n")
(out / "client.toml").write_text(
    'network_id_file = "genesis.expected_hash"\n'
    f'torii_url = "http://127.0.0.1:{args.base_api_port}/"\n'
    '\n[account]\nchain_discriminant = 753\nprivate_key = "802620CLIENTSECRET"\npublic_key  = "ed0120CLIENT"\n'
)
(out / "start.sh").write_text("""#!/usr/bin/env bash
set -euo pipefail
DIR=$(cd "$(dirname "$0")" && pwd)
[ "$1" = "--peer-index" ] || exit 2
i="$2"
FRESH=""
if [ ! -d "$DIR/state/peer$i/sumeragi-records" ]; then FRESH="--sumeragi-assert-fresh-key"; fi
# Like the kagami launcher: LOG_LEVEL and LOG_FILTER reach the node, empty when unset.
LOG_LEVEL="${LOG_LEVEL:-info}" LOG_FILTER="${LOG_FILTER:-}" nohup "$IROHAD_BIN" --config "$DIR/peer$i.toml" $FRESH >> "$DIR/peer$i.log" 2>&1 &
echo $! > "$DIR/peer$i.pid"
""")
print("localnet ready")
'''

FAKE_NODE = r'''
import hashlib, http.server, json, os, signal, sys, threading, time
try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 uses the pinned backport (scripts/requirements.txt).
    import tomli as tomllib
from datetime import datetime, timezone
from pathlib import Path
config_path = Path(sys.argv[sys.argv.index("--config") + 1])
failure = config_path.with_suffix(".fail-once")
if failure.exists():
    failure.unlink()
    print("fake startup failure", flush=True)
    sys.exit(3)
config = tomllib.loads(config_path.read_text())
# Like the node's config reader, LOG_* environment variables override the file.
logger = {key: os.environ.get(f"LOG_{key.upper()}", config["logger"].get(key)) for key in ("format", "level", "filter")}
assert logger["format"] == "json", logger
assert "iroha_core::sumeragi::driver::audit=debug" in (logger["filter"] or "").split(","), logger
def check(literal):
    body, checksum = literal.split("@")[-1][len("addr:"):].rsplit("#", 1)
    value = 0xFFFF
    for byte in ("addr:" + body).encode():
        value ^= byte << 8
        for _ in range(8):
            value = ((value << 1) ^ 0x1021) & 0xFFFF if value & 0x8000 else (value << 1) & 0xFFFF
    assert f"{value:04X}" == checksum, literal
for literal in config["trusted_peers"] + [config["network"]["address"], config["network"]["public_address"]]:
    check(literal)
port = int(config["torii"]["address"].rsplit(":", 1)[1])
store = Path(config["kura"]["store_dir"])
store.mkdir(parents=True, exist_ok=True)
records = Path(config["sumeragi"]["records_dir"])
if "--sumeragi-assert-fresh-key" in sys.argv:
    assert not records.exists(), "the assertion is passed only at the first boot"
records.mkdir(parents=True, exist_ok=True)
height_file = store / "height"
height = int(height_file.read_text()) if height_file.exists() else 0
key = hashlib.sha256(str(port).encode()).hexdigest() * 2
instance = "11" * 32

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"Healthy" if self.path == "/health" else json.dumps({"txs_approved": height * 3}).encode()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass

server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
signal.signal(signal.SIGTERM, lambda *_: os._exit(0))

def emit(fields):
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    print(json.dumps({"timestamp": stamp, "level": "INFO", "fields": fields,
                      "target": "iroha_core::sumeragi::driver::audit"}), flush=True)

def persist_height(path, value):
    # A scheduled crash can interrupt truncation before the first written byte.
    # Publish the complete successor atomically and retain the applied file until then.
    staging = path.with_suffix(".pending")
    staging.write_text(str(value))
    staging.replace(path)

while True:
    height += 1
    block = hashlib.sha256(f"block-{height}".encode()).hexdigest()
    result = hashlib.sha256(f"result-{height}".encode()).hexdigest()
    emit({"message": "sumeragi record durable", "instance": instance, "key": key,
          "height": height, "epoch": 1, "signed": f"prepare:0:{block}:{result}"})
    persist_height(height_file, height)
    emit({"message": "sumeragi block applied", "instance": instance, "height": height,
          "view": 0, "origin_view": 0, "block": block, "result": result,
          "proposer": height % 4, "payload_bytes": 64})
    time.sleep(0.2)
'''

FAKE_CLI = r'''
import json, sys, time
try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 uses the pinned backport (scripts/requirements.txt).
    import tomli as tomllib
from pathlib import Path
arguments = sys.argv[1:]
assert arguments[0] == "--config", arguments
# Like the client: a relative network_id_file resolves against the config's directory.
config_path = Path(arguments[1])
config = tomllib.loads(config_path.read_text())
network_id = Path(config["network_id_file"])
assert (config_path.parent / network_id).is_file(), network_id
if arguments[2:5] == ["tools", "address", "convert"]:
    print("CLI banner")
    print("soraufake-" + arguments[5])
    sys.exit(0)
if arguments[2:5] == ["ledger", "asset", "mint"]:
    # Only the genesis account (the fee asset's registrant) may mint; the record is for the test.
    assert config["account"]["public_key"] == "ed0120GENESIS", config["account"]
    assert config["account"]["private_key"] == "802620GENESISSECRET"
    assert config_path.stat().st_mode & 0o777 == 0o600
    flags = dict(zip(arguments[5::2], arguments[6::2]))
    (config_path.parent / "minted.json").write_text(json.dumps(flags))
    sys.exit(0)
assert "tx" in arguments and "ping" in arguments, arguments
assert arguments[arguments.index("tx") + 1] == "--fee-payer"
if "--no-wait" in arguments:
    count = int(arguments[arguments.index("--count") + 1])
    print(f"Submitted {count}/{count} ping transactions without confirmation")
else:
    time.sleep(0.05)
'''


def write_executable(path: Path, body: str) -> None:
    path.write_text(f"#!{sys.executable}\n" + textwrap.dedent(body))
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def free_base(count: int, avoid: set[int]) -> int:
    """A base port with ``count`` consecutive free ports outside ``avoid``."""
    rng = random.Random()
    for _ in range(200):
        base = rng.randrange(20_000, 60_000)
        ports = range(base, base + count)
        if avoid.intersection(ports):
            continue
        if all(soak.port_free(port) for port in ports):
            return base
    raise RuntimeError("no free port range")


class FakeNodePersistenceTests(unittest.TestCase):
    def test_interrupted_original_node_write_preserves_last_applied_height(self) -> None:
        """Interrupt the actual fake-node persistence call before its first byte."""
        source = ast.parse(FAKE_NODE)
        loop = next(node for node in source.body if isinstance(node, ast.While))
        write = next(
            statement for statement in loop.body
            if isinstance(statement, ast.Expr)
            and any(
                isinstance(node, ast.Name) and node.id == "height_file"
                for node in ast.walk(statement)
            )
        )
        definitions = ast.Module(
            body=[node for node in source.body if isinstance(node, ast.FunctionDef)],
            type_ignores=[],
        )
        operation = ast.Module(body=[write], type_ignores=[])
        with tempfile.TemporaryDirectory() as tmp:
            height_file = Path(tmp) / "height"
            height_file.write_text("41")
            scope = {"Path": Path, "height_file": height_file, "height": 42}
            exec(compile(definitions, "fake-node-definitions", "exec"), scope)

            def interrupted_write(path: Path, *_args: object, **_kwargs: object) -> int:
                with path.open("w"):
                    pass
                raise OSError("interrupted after truncation, before writing")

            with mock.patch.object(Path, "write_text", autospec=True, side_effect=interrupted_write):
                with self.assertRaisesRegex(OSError, "interrupted after truncation"):
                    exec(compile(operation, "fake-node-height-write", "exec"), scope)
            self.assertEqual(height_file.read_text(), "41")
            exec(compile(operation, "fake-node-height-write", "exec"), scope)
            self.assertEqual(height_file.read_text(), "42")


class OrchestratorRunTests(unittest.TestCase):
    def test_a_short_run_with_kills_and_proxy_loss_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bins = root / "bin"
            bins.mkdir()
            write_executable(bins / "kagami", FAKE_KAGAMI)
            write_executable(bins / "iroha3d", FAKE_NODE)
            write_executable(bins / "iroha", FAKE_CLI)
            api = free_base(4, set())
            p2p = free_base(4, set(range(api, api + 4)))
            proxy = free_base(4, set(range(api, api + 4)) | set(range(p2p, p2p + 4)))
            out = root / "run"
            status = soak.main(
                [
                    "--validators", "4",
                    "--faults", "kill,net",
                    "--net-mode", "proxy",
                    "--seed", "11",
                    "--duration", "26s",
                    "--warmup", "4s",
                    "--final-quiet", "9s",
                    "--fault-window", "2-3",
                    "--fault-gap", "2-3",
                    "--live-bound", "8s",
                    "--warmup-heights", "2",
                    "--max-gap-p99-ms", "2000",
                    "--max-gap-ms", "5000",
                    "--max-latency-p99-ms", "5000",
                    "--min-tps", "0.5",
                    "--load-tps", "3",
                    "--probe-interval", "1s",
                    "--bin-dir", str(bins),
                    "--out", str(out),
                    "--base-api-port", str(api),
                    "--base-p2p-port", str(p2p),
                    "--base-proxy-port", str(proxy),
                ]
            )
            verdict = json.loads((out / "verdict.json").read_text())
            self.assertEqual(status, soak.EXIT_OK, json.dumps(verdict, indent=1))
            self.assertTrue(verdict["ok"])
            timeline = json.loads((out / "timeline.json").read_text())
            kinds = {window["kind"] for window in timeline["windows"]}
            self.assertEqual(kinds, {"kill", "net"})
            killed = [boot for boot in timeline["boots"] if boot["ended"] == "killed"]
            self.assertTrue(killed)
            for boot in killed:
                self.assertTrue((out / "logs" / boot["node"] / f"boot{boot['index']}.log").is_file())
                self.assertTrue((out / "logs" / boot["node"] / f"boot{boot['index'] + 1}.log").is_file())
            self.assertEqual(verdict["timeline"]["kills"], len(killed))
            config = tomllib.loads((out / "net" / "peer0.toml").read_text())
            self.assertEqual(config["logger"]["filter"], soak.logs.AUDIT_LOG_FILTER)
            self.assertEqual(
                config["nexus"]["storage"]["local_budget_bytes"],
                soak.PROFILES["smoke"]["storage_budget_mb"] * 1024 * 1024,
            )
            self.assertIs(config["sccp"]["light_client_keeper"]["enabled"], False)
            # The genesis account funded the load's account with the fee asset before the load.
            minted = json.loads((out / "clients" / "minted.json").read_text())
            self.assertEqual(
                minted,
                {"--definition": "FAKEXOR", "--account": "soraufake-ed0120CLIENT", "--quantity": soak.DEFAULT_FUND, "--fee-payer": "authority"},
            )
            run = json.loads((out / "run.json").read_text())
            self.assertEqual(run["funding"], {"account": "soraufake-ed0120CLIENT", "asset": "FAKEXOR", "quantity": soak.DEFAULT_FUND})
            self.assertEqual(config["network"]["address"], soak.addr_literal("0.0.0.0", p2p))
            self.assertEqual(config["network"]["public_address"], soak.addr_literal("127.0.0.1", proxy))
            self.assertEqual(config["trusted_peers"][3], f"k3@{soak.addr_literal('127.0.0.1', proxy + 3)}")
            load = json.loads((out / "load.json").read_text())
            self.assertGreater(load["submitted"], 0)
            self.assertTrue(any(probe["ok"] for probe in load["probes"]))
            self.assertGreater(verdict["oracles"]["O-PERF"]["checked"]["committed_tps"], 0.5)
            self.assertIn("proxy", verdict)
            self.assertFalse((out / "net" / "state").exists())
            # The verdict is reproducible offline.
            self.assertEqual(soak.main(["--analyze", str(out)]), soak.EXIT_OK)

    def test_a_peer_that_exits_while_starting_is_restarted_and_judged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bins = root / "bin"
            bins.mkdir()
            write_executable(bins / "kagami", FAKE_KAGAMI)
            write_executable(bins / "iroha3d", FAKE_NODE)
            write_executable(bins / "iroha", FAKE_CLI)
            api = free_base(4, set())
            p2p = free_base(4, set(range(api, api + 4)))
            out = root / "run"
            with mock.patch.dict(os.environ, {"SOAK_TEST_FAIL_FIRST_BOOT": "peer1"}):
                status = soak.main(
                    [
                        "--validators", "4", "--faults", "none", "--seed", "2", "--duration", "8s",
                        "--live-bound", "8s", "--warmup-heights", "2", "--max-gap-p99-ms", "2000",
                        "--max-gap-ms", "5000", "--max-latency-p99-ms", "5000", "--min-tps", "0.5",
                        "--load-tps", "3", "--probe-interval", "1s", "--bin-dir", str(bins), "--out", str(out),
                        "--base-api-port", str(api), "--base-p2p-port", str(p2p),
                    ]
                )
            verdict = json.loads((out / "verdict.json").read_text())
            self.assertEqual(status, soak.EXIT_VIOLATION, json.dumps(verdict, indent=1))
            live = verdict["oracles"]["O-LIVE"]["violations"]
            self.assertEqual(
                [(entry["kind"], entry["node"], entry["boot"]) for entry in live],
                [("unexpected-exit", "peer1", 0)],
            )
            self.assertTrue(all(verdict["oracles"][name]["ok"] for name in ("O-AGR", "O-SIGN", "O-PERF")))
            self.assertIn("fake startup failure", (out / "logs" / "peer1" / "boot0.log").read_text())
            self.assertTrue((out / "logs" / "peer1" / "boot1.log").is_file())

    def test_a_kagami_failure_is_a_harness_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bins = root / "bin"
            bins.mkdir()
            write_executable(bins / "kagami", "import sys\nprint('genesis signing failed', file=sys.stderr)\nsys.exit(1)\n")
            write_executable(bins / "iroha3d", FAKE_NODE)
            write_executable(bins / "iroha", FAKE_CLI)
            api = free_base(4, set())
            p2p = free_base(4, set(range(api, api + 4)))
            out = root / "run"
            status = soak.main(
                ["--validators", "4", "--faults", "none", "--seed", "1", "--duration", "10s", "--live-bound", "8s", "--bin-dir", str(bins), "--out", str(out),
                 "--base-api-port", str(api), "--base-p2p-port", str(p2p)]
            )
            self.assertEqual(status, soak.EXIT_HARNESS)
            self.assertIn("genesis signing failed", (out / "harness-error.txt").read_text())
            self.assertFalse((out / "verdict.json").exists())


if __name__ == "__main__":
    unittest.main()
