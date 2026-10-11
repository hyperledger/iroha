#!/usr/bin/env python3
"""Optional Sumeragi fault diagnostics: a real multi-process network judged from node logs.

This is the soak of ``specs/sumeragi.md`` §13.5 (last bullet) and §14 item 5 (goal S7 in
``specs/sumeragi_goals.md``): ``n = 4`` and ``n = 22`` validators, P2P loss of 10–30 % with delay
spikes, random ``kill -9`` and restart, and disk-full injection. On-chain governance owns
deployment policy for Taira and production; no fixed duration or soak verdict is a cutover
prerequisite. The profile named ``gate`` selects optional long-run diagnostic defaults.
O-AGR, O-SIGN, O-LIVE and O-PERF are computed only from what the nodes logged
(``scripts/sumeragi_soak_logs.py``); the verdict is written as JSON and the exit status is
non-zero on any violation.

The network is a ``kagami localnet`` (fresh genesis, one start script per peer, which passes
``--sumeragi-assert-fresh-key`` on a peer's first boot only). The soak rewrites each peer
config's ``[logger]`` to the JSON format with the audit filter
(``iroha_core::sumeragi::driver::audit=debug``), and in proxy mode points every P2P address at
a userspace proxy. Faults are injected by ``scripts/sumeragi_soak_faults.py``: ``tc netem`` in a
network namespace on Linux, the TCP proxy on macOS (the difference is documented there), a
size-limited volume for one peer's state, and ``SIGKILL``.

Typical runs::

    # Build once (release for performance diagnostics, debug is fine for a smoke run).
    cargo build --release -p irohad --bin iroha3d -p iroha_kagami --bin kagami -p iroha_cli --bin iroha

    # Smoke: a few minutes, n = 4, kill -9 and proxy loss.
    python3 scripts/sumeragi_soak.py --profile smoke --validators 4 --faults kill,net \
        --net-mode proxy --bin-dir target/release --out artifacts/sumeragi-soak/smoke

    # Optional long diagnostic: 24 h (Linux, netem in a namespace).
    python3 scripts/sumeragi_soak.py --profile gate --validators 22 --seed 7 \
        --bin-dir target/release --out artifacts/sumeragi-soak/gate-n22

    # Recompute the verdict of a finished run from its logs.
    python3 scripts/sumeragi_soak.py --analyze artifacts/sumeragi-soak/gate-n22

Operator runbook: ``specs/runbooks/sumeragi_taira_reset.md`` (section "Optional fault diagnostics").
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import math
import os
import random
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Sequence

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))

import sumeragi_soak_faults as faults  # noqa: E402
import sumeragi_soak_logs as logs  # noqa: E402

NAMESPACE_ENV = "SUMERAGI_SOAK_NAMESPACE"
EXIT_OK = 0
EXIT_VIOLATION = 1
EXIT_HARNESS = 2

# The node logger of every peer: JSON lines with the audit filter (``[logger]`` keys). The same
# values are exported as ``LOG_FORMAT``, ``LOG_LEVEL`` and ``LOG_FILTER`` to the start script,
# because a node's environment overrides its config file and the generated start script
# exports ``LOG_LEVEL`` and ``LOG_FILTER`` (empty when unset, which would drop the DEBUG
# durable-record lines and blind O-SIGN).
NODE_LOGGER = {"format": "json", "level": "info", "filter": logs.AUDIT_LOG_FILTER}
# The generated client account starts with a small fee-asset allocation that a sustained load
# spends within minutes (about 0.002 per `Log` transaction at the default fee schedule); the
# schedule is part of the execution policy genesis signs, so the soak funds the account instead
# of quoting zero fees. One million covers a 24 h diagnostic at 20 transactions per second 10 times over.
DEFAULT_FUND = "1000000"
NODE_LOGGER_ENV = {f"LOG_{key.upper()}": value for key, value in NODE_LOGGER.items()}

# Profiles: presets that explicit options override.
PROFILES: dict[str, dict[str, Any]] = {
    "smoke": {
        "duration": "5m",
        "warmup": "45s",
        "final_quiet": "100s",
        "fault_window": (15.0, 30.0),
        "fault_gap": (20.0, 40.0),
        "live_bound": "90s",
        "max_gap_p99_ms": 10_000.0,
        "max_gap_ms": 60_000.0,
        "max_latency_p99_ms": 60_000.0,
        "min_tps_ratio": 0.1,
        "warmup_heights": 5,
        "load_tps": 10.0,
        "disk_size_mb": 2048,
        "storage_budget_mb": 1024,
    },
    "gate": {
        "duration": "24h",
        "warmup": "120s",
        # Longer than B_live for every committee of 4..31 (at most about 17.8 min at n = 31).
        "final_quiet": "20m",
        "fault_window": (15.0, 60.0),
        "fault_gap": (60.0, 180.0),
        "live_bound": None,  # the §8.2 bound
        "max_gap_p99_ms": 3_000.0,
        "max_gap_ms": 20_000.0,
        "max_latency_p99_ms": 15_000.0,
        "min_tps_ratio": 0.5,
        "warmup_heights": 20,
        "load_tps": 20.0,
        "disk_size_mb": 16_384,
        # Kura gets a quarter of the budget (the default Nexus storage weights) and keeps about
        # 1 KiB per committed transaction: 3 GiB hold a day at 20 transactions per second
        # (about 1.7 GiB) with room to spare.
        "storage_budget_mb": 12_288,
    },
}

_DURATION_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*(ms|s|m|h|d)?\s*$")


def parse_duration(text: str) -> float:
    """Seconds of ``300``, ``300s``, ``5m``, ``24h``, ``1d`` or ``500ms``."""
    match = _DURATION_RE.match(str(text))
    if match is None:
        raise argparse.ArgumentTypeError(f"not a duration: {text!r}")
    value = float(match.group(1))
    unit = match.group(2) or "s"
    return value * {"ms": 0.001, "s": 1.0, "m": 60.0, "h": 3600.0, "d": 86400.0}[unit]


def parse_range(text: str) -> tuple[float, float]:
    """``a-b`` or a single value as ``(a, b)``."""
    parts = str(text).split("-")
    if len(parts) == 1:
        value = float(parts[0])
        return value, value
    if len(parts) != 2:
        raise argparse.ArgumentTypeError(f"not a range: {text!r}")
    low, high = float(parts[0]), float(parts[1])
    if low > high:
        raise argparse.ArgumentTypeError(f"empty range: {text!r}")
    return low, high


def parse_loss(text: str) -> tuple[float, float]:
    """Loss as a fraction or percent range (``0.1-0.3`` or ``10-30``)."""
    low, high = parse_range(text)
    if high > 1.0:
        low, high = low / 100.0, high / 100.0
    if not (0.0 <= low <= high < 1.0):
        raise argparse.ArgumentTypeError(f"loss must lie in [0, 1): {text!r}")
    return low, high


def validators_arg(text: str) -> int:
    """An exact ``3f + 1`` committee of 4..31 validators (genesis rejects anything else)."""
    value = int(text)
    if not (4 <= value <= 31 and (value - 1) % 3 == 0):
        raise argparse.ArgumentTypeError(
            f"the committee must be exactly 3f + 1 with 1 <= f <= 10 (4, 7, ..., 31), got {value}"
        )
    return value


def build_parser() -> argparse.ArgumentParser:
    """The command line."""
    parser = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--analyze", type=Path, metavar="RUN_DIR", help="recompute the verdict of a finished run")
    parser.add_argument("--profile", choices=sorted(PROFILES), default="smoke", help="optional diagnostic preset (default smoke); no deployment prerequisite")
    parser.add_argument("--duration", type=parse_duration, help="run length after the network is up (e.g. 5m, 24h)")
    parser.add_argument("--validators", type=validators_arg, default=4, help="3f + 1 validators (4 or 22 for the optional long diagnostic)")
    parser.add_argument("--loss", type=parse_loss, default=(0.10, 0.30), help="P2P loss range of a net fault (default 10-30 %%)")
    parser.add_argument("--seed", type=int, default=None, help="seed of the fault plan and link noise (default: random, recorded)")
    parser.add_argument("--out", type=Path, help="run directory (network, logs, verdict)")
    parser.add_argument("--faults", default="kill,disk,net", help="comma-separated fault kinds: kill, disk, net (or 'none')")
    parser.add_argument(
        "--net-mode",
        choices=("auto", "proxy", "netem", "off"),
        default="auto",
        help="how net faults are injected: netem (Linux namespace), proxy (userspace TCP proxy), auto (netem on Linux, proxy elsewhere)",
    )
    parser.add_argument("--bin-dir", type=Path, help="directory with iroha3d, kagami and iroha (default target/release, else target/debug)")
    parser.add_argument("--warmup", type=parse_duration, help="fault-free time before the first fault")
    parser.add_argument("--final-quiet", type=parse_duration, help="fault-free time after the last fault")
    parser.add_argument("--fault-window", type=parse_range, help="fault window length range in seconds (e.g. 15-60)")
    parser.add_argument("--fault-gap", type=parse_range, help="fault-free gap range between windows in seconds")
    parser.add_argument("--max-kill", type=int, default=None, help="validators killed at once at most (default 1, capped at f)")
    parser.add_argument("--disk-node", type=int, default=None, help="peer index whose state lives on the size-limited volume (default: the last peer)")
    parser.add_argument("--disk-size-mb", type=int, help="size of the disk-full volume")
    parser.add_argument(
        "--storage-budget-mb",
        type=int,
        help="nexus.storage.local_budget_bytes of every peer in MiB; must fit on the disk-full volume",
    )
    parser.add_argument("--reset-ratio", type=float, default=0.005, help="proxy: connection resets per chunk as a fraction of the loss (default 0.005)")
    parser.add_argument("--load-tps", type=float, help="offered transactions per second")
    parser.add_argument("--probe-interval", type=parse_duration, default=10.0, help="interval of commit-latency probes")
    parser.add_argument("--fee-payer", default="authority", help="fee source of the load's transactions (iroha tx --fee-payer)")
    parser.add_argument(
        "--fund",
        default=DEFAULT_FUND,
        help=f"fee-asset quantity the genesis account mints to the load's account before the load starts (0: none; default {DEFAULT_FUND})",
    )
    parser.add_argument("--live-bound", type=parse_duration, help="O-LIVE bound (default: B_live of spec §8.2 for the committee size)")
    parser.add_argument("--live-lag-heights", type=int, default=64, help="lag term of B_live in heights (default one sync batch)")
    parser.add_argument("--max-gap-p99-ms", type=float, help="O-PERF: p99 commit gap in fault-free intervals")
    parser.add_argument("--max-gap-ms", type=float, help="O-PERF: largest commit gap in fault-free intervals")
    parser.add_argument("--max-latency-p99-ms", type=float, help="O-PERF: p99 client-observed commit latency")
    parser.add_argument("--min-tps", type=float, help="O-PERF: committed transactions per second over the run")
    parser.add_argument("--warmup-heights", type=int, help="O-PERF: commits skipped after every heal (spec Appendix E8)")
    parser.add_argument("--base-api-port", type=int, default=18080)
    parser.add_argument("--base-p2p-port", type=int, default=11337)
    parser.add_argument("--base-proxy-port", type=int, default=None, help="proxy mode: first proxy port (default base P2P port + 100)")
    parser.add_argument("--keep-state", action="store_true", help="keep the network state directories after the run")
    return parser


# ---------------------------------------------------------------------------------------------
# Config rewriting
# ---------------------------------------------------------------------------------------------


def set_toml_keys(text: str, section: str, values: dict[str, str]) -> str:
    """Set ``key = value`` (``value`` already TOML-encoded) inside ``[section]`` of ``text``.

    Keys present in the section are replaced in place; missing keys are appended to the
    section, which is created at the end of the document when absent.
    """
    lines = text.splitlines()
    header = f"[{section}]"
    start = next((index for index, line in enumerate(lines) if line.strip() == header), None)
    if start is None:
        suffix = [""] if lines and lines[-1].strip() else []
        lines.extend(suffix + [header] + [f"{key} = {value}" for key, value in values.items()])
        return "\n".join(lines) + "\n"
    end = next(
        (index for index in range(start + 1, len(lines)) if lines[index].lstrip().startswith("[")),
        len(lines),
    )
    pending = dict(values)
    for index in range(start + 1, end):
        key = lines[index].split("=", 1)[0].strip()
        if "=" in lines[index] and key in pending:
            lines[index] = f"{key} = {pending.pop(key)}"
    insert_at = end
    while insert_at > start + 1 and not lines[insert_at - 1].strip():
        insert_at -= 1
    lines[insert_at:insert_at] = [f"{key} = {value}" for key, value in pending.items()]
    return "\n".join(lines) + "\n"


def literal_checksum(tag: str, body: str) -> str:
    """The checksum of a Norito literal ``<tag>:<body>#<crc>``: CRC-16 (polynomial 0x1021,
    initial value 0xFFFF) over ``<tag>:<body>``, four uppercase hex digits
    (``crates/norito/src/literal.rs``)."""
    crc = 0xFFFF
    for byte in f"{tag}:{body}".encode():
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return f"{crc:04X}"


def addr_literal(host: str, port: int) -> str:
    """The canonical address literal ``addr:<host>:<port>#<crc>`` of the node configuration."""
    body = f"{host}:{port}"
    return f"addr:{body}#{literal_checksum('addr', body)}"


_ADDR_LITERAL_RE = re.compile(r"addr:(?P<host>[^\s\"'#]+):(?P<port>\d+)#(?P<crc>[0-9A-Fa-f]{4})")
_PLAIN_ADDR_RE = re.compile(r"(?P<host>(?<=[\"'@])[\w.\-]+|\[[0-9A-Fa-f:.]+\]):(?P<port>\d+)(?=[\"'])")


def rewrite_p2p_ports(text: str, mapping: dict[int, int]) -> str:
    """Point every advertised P2P address of the ports in ``mapping`` at the mapped proxy port.

    Every address with a mapped port is rewritten — the checksummed literals
    ``addr:<host>:<port>#<crc>`` of the node configuration (with a recomputed checksum) and
    plain ``host:port`` strings — in ``trusted_peers`` and ``network.public_address``, but not
    the bind address ``network.address``: each peer still listens on its own port while every
    peer dials the proxies.
    """

    def literal(match: re.Match[str]) -> str:
        port = int(match["port"])
        if port not in mapping:
            return match.group(0)
        return addr_literal(match["host"], mapping[port])

    def plain(match: re.Match[str]) -> str:
        port = int(match["port"])
        if port not in mapping:
            return match.group(0)
        return f"{match['host']}:{mapping[port]}"

    lines = text.splitlines()
    section = None
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("[") and "=" not in stripped.split("]", 1)[0]:
            section = stripped.strip("[]").strip()
            continue
        key = stripped.split("=", 1)[0].strip() if "=" in stripped else None
        if section == "network" and key == "address":
            continue
        rewritten = _ADDR_LITERAL_RE.sub(literal, line)
        if rewritten == line:
            rewritten = _PLAIN_ADDR_RE.sub(plain, line)
        lines[index] = rewritten
    return "\n".join(lines) + "\n"


def toml_string(value: str) -> str:
    """A TOML basic string."""
    return json.dumps(value)


_TOML_HEADER_RE = re.compile(r"^(?P<open>\[\[?)\s*(?P<name>[A-Za-z0-9_.\-]+)\s*\]\]?\s*(#.*)?$")


def toml_string_value(text: str, section: str, key: str) -> Optional[str]:
    """The basic-string value of ``key`` in ``[section]`` of ``text`` (``None`` when absent)."""
    current = None
    for line in text.splitlines():
        stripped = line.strip()
        header = _TOML_HEADER_RE.match(stripped)
        if header is not None:
            # An array-of-tables entry ([[name]]) is never the plain table asked for.
            current = header["name"] if header["open"] == "[" else f"[[{header['name']}]]"
            continue
        if current != section or "=" not in stripped:
            continue
        name, value = (part.strip() for part in stripped.split("=", 1))
        if name == key:
            match = re.match(r'"((?:[^"\\]|\\.)*)"', value)
            return json.loads(f'"{match.group(1)}"') if match else None
    return None


def absolutize_path_key(text: str, key: str, base: Path) -> str:
    """Make the first ``key = "<path>"`` of ``text`` absolute against ``base`` (a relative path
    names a file next to the original config, which a copy elsewhere must still name)."""

    def absolute(match: re.Match[str]) -> str:
        path = Path(match["path"])
        if path.is_absolute():
            return match.group(0)
        return match["key"] + toml_string(str(base / path))

    return re.sub(
        rf'^(?P<key>{re.escape(key)}\s*=\s*)"(?P<path>[^"]*)"',
        absolute,
        text,
        count=1,
        flags=re.MULTILINE,
    )


# ---------------------------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------------------------


@dataclass
class PeerState:
    """One peer process and its lifetimes."""

    index: int
    pid: Optional[int] = None
    boot: int = -1
    boot_start_ms: float = 0.0
    killed: bool = False


@dataclass
class BootRecord:
    """A finished or running lifetime (for ``timeline.json``)."""

    node: str
    index: int
    start_ms: float
    end_ms: Optional[float]
    ended: str


def now_ms() -> float:
    """Wall clock in milliseconds (log timestamps are wall clock too)."""
    return time.time() * 1000.0


def process_running(pid: int) -> bool:
    """Whether ``pid`` exists and is not a zombie.

    Peers are started by the start script's launcher, which exits, so their parent is the
    init process of the (container's) PID namespace; one that never reaps would leave a killed
    peer as a zombie forever, which ``kill(pid, 0)`` still reports as present.
    """
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    stat = Path(f"/proc/{pid}/stat")
    if stat.exists():
        try:
            state = stat.read_text().rsplit(")", 1)[1].split()[0]
        except (OSError, IndexError):
            return True
        return state not in ("Z", "X")
    return True


def port_free(port: int, host: str = "127.0.0.1") -> bool:
    """Whether ``host:port`` can be bound now."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind((host, port))
        except OSError:
            return False
    return True


class Localnet:
    """A ``kagami localnet`` with per-boot log files and ``SIGKILL`` restarts."""

    def __init__(self, run_dir: Path, bins: dict[str, Path], validators: int, seed: int, base_api: int, base_p2p: int) -> None:
        self.run_dir = run_dir
        self.net_dir = run_dir / "net"
        self.log_dir = run_dir / "logs"
        self.bins = bins
        self.validators = validators
        self.seed = seed
        self.base_api = base_api
        self.base_p2p = base_p2p
        self.peers = [PeerState(index) for index in range(validators)]
        self.boots: list[BootRecord] = []
        self.lock = threading.Lock()

    def node(self, index: int) -> str:
        """The node name used in logs and the verdict."""
        return f"peer{index}"

    def api_port(self, index: int) -> int:
        """Torii port of a peer."""
        return self.base_api + index

    def p2p_port(self, index: int) -> int:
        """P2P port of a peer."""
        return self.base_p2p + index

    def config(self, index: int) -> Path:
        """A peer's config file."""
        return self.net_dir / f"peer{index}.toml"

    def state_dir(self, index: int) -> Path:
        """A peer's state root (Kura store, Sumeragi records, installation log)."""
        return self.net_dir / "state" / f"peer{index}"

    def generate(self) -> None:
        """Run ``kagami localnet generate`` (fresh genesis and node configurations)."""
        command = [
            str(self.bins["kagami"]),
            "localnet",
            "generate",
            "--peers",
            str(self.validators),
            "--seed",
            f"sumeragi-soak-{self.seed}",
            "--base-api-port",
            str(self.base_api),
            "--base-p2p-port",
            str(self.base_p2p),
            "--out-dir",
            str(self.net_dir),
        ]
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        (self.run_dir / "kagami-localnet.log").write_text(result.stdout + "\n" + result.stderr)
        if result.returncode != 0:
            raise RuntimeError(
                f"kagami localnet failed ({result.returncode}); see {self.run_dir / 'kagami-localnet.log'}:\n"
                + "\n".join((result.stdout + result.stderr).strip().splitlines()[-12:])
            )
        for index in range(self.validators):
            if not self.config(index).is_file():
                raise RuntimeError(f"kagami localnet wrote no {self.config(index)}")
        if not (self.net_dir / "start.sh").is_file():
            raise RuntimeError("kagami localnet wrote no start.sh")

    def patch_configs(self, proxy_ports: Optional[dict[int, int]], storage_budget_bytes: int) -> None:
        """JSON logs with the audit filter, an explicit Nexus storage budget, no SCCP light-client
        keeper and, in proxy mode, advertised P2P ports at the proxies.

        All of these are node-local (outside the execution policy that genesis signs). Without
        the budget a node derives one from the free space of its filesystem and refuses to start
        when the reserved headroom leaves none, which a nearly full host or the disk-full peer's
        small volume would. The keeper polls public Ethereum RPC endpoints by default, which a
        consensus soak must not depend on or contact.
        """
        mapping = (
            {self.p2p_port(index): proxy_ports[index] for index in range(self.validators)}
            if proxy_ports
            else {}
        )
        for index in range(self.validators):
            path = self.config(index)
            text = path.read_text()
            text = set_toml_keys(
                text, "logger", {key: toml_string(value) for key, value in NODE_LOGGER.items()}
            )
            text = set_toml_keys(text, "nexus.storage", {"local_budget_bytes": str(storage_budget_bytes)})
            text = set_toml_keys(text, "sccp.light_client_keeper", {"enabled": "false"})
            if mapping:
                text = rewrite_p2p_ports(text, mapping)
            path.write_text(text)

    def move_kura_into_state(self, index: int) -> Path:
        """Put a peer's Kura store (and with it the sibling Sumeragi body store) under its state
        root, so that one volume holds every durable consensus file of the peer: blocks,
        bodies, safety records and the installation log."""
        path = self.config(index)
        target = self.state_dir(index) / "kura"
        text = path.read_text()
        match = re.search(r'(?ms)^\[kura\]\s*$.*?^store_dir\s*=\s*"([^"]*)"', text)
        if match is None:
            raise RuntimeError(f"{path} has no [kura] store_dir")
        source = Path(match.group(1))
        if not source.is_absolute():
            source = (path.parent / source).resolve()
        text = set_toml_keys(text, "kura", {"store_dir": toml_string(str(target))})
        path.write_text(text)
        self.state_dir(index).mkdir(parents=True, exist_ok=True)
        if source.exists():
            shutil.move(str(source), str(target))
        return target

    def client_config(self, index: int) -> Path:
        """A client config that talks to peer ``index``'s Torii.

        The copy lives outside the network directory, so its relative ``network_id_file`` is
        made absolute (the client resolves paths against the config's directory). It holds the
        client's private key: it is written owner-only and renamed into place, so a concurrent
        caller never reads a partial file.
        """
        path = self.run_dir / "clients" / f"client{index}.toml"
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            text = (self.net_dir / "client.toml").read_text()
            text = re.sub(
                r'^torii_url\s*=\s*"[^"]*"',
                f'torii_url = "http://127.0.0.1:{self.api_port(index)}/"',
                text,
                count=1,
                flags=re.MULTILINE,
            )
            text = absolutize_path_key(text, "network_id_file", self.net_dir)
            staging = path.with_name(f"{path.name}.{threading.get_ident()}.tmp")
            descriptor = os.open(staging, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(descriptor, "w") as handle:
                handle.write(text)
            os.replace(staging, path)
        return path

    def _rotate_log(self, index: int, boot: int) -> None:
        source = self.net_dir / f"peer{index}.log"
        target_dir = self.log_dir / self.node(index)
        target_dir.mkdir(parents=True, exist_ok=True)
        if source.exists():
            source.rename(target_dir / f"boot{boot}.log")

    def start(self, index: int) -> None:
        """Start a peer through the generated start script (a new boot, a fresh log file)."""
        peer = self.peers[index]
        with self.lock:
            if peer.pid is not None:
                raise RuntimeError(f"peer{index} is already running")
            if peer.boot >= 0:
                self._rotate_log(index, peer.boot)
            peer.boot += 1
        env = dict(os.environ)
        env["IROHAD_BIN"] = str(self.bins["iroha3d"])
        env["IROHA_CLI"] = str(self.bins["iroha"])
        env.update(NODE_LOGGER_ENV)
        result = subprocess.run(
            ["bash", str(self.net_dir / "start.sh"), "--peer-index", str(index)],
            cwd=self.net_dir,
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
        with (self.run_dir / "start-scripts.log").open("a") as log:
            log.write(f"--- peer{index} boot {peer.boot}: exit {result.returncode}\n{result.stdout}{result.stderr}\n")
        if result.returncode != 0:
            raise RuntimeError(f"start.sh --peer-index {index} failed ({result.returncode}): {result.stderr.strip()[-400:]}")
        pid_text = (self.net_dir / f"peer{index}.pid").read_text().strip()
        with self.lock:
            peer.pid = int(pid_text)
            peer.boot_start_ms = now_ms()
            peer.killed = False

    def alive(self, index: int) -> bool:
        """Whether the peer's process runs (a zombie nobody reaped yet counts as gone)."""
        pid = self.peers[index].pid
        return pid is not None and process_running(pid)

    def _end_boot(self, index: int, ended: str) -> None:
        peer = self.peers[index]
        self.boots.append(
            BootRecord(self.node(index), peer.boot, peer.boot_start_ms, now_ms(), ended)
        )
        peer.pid = None

    def kill(self, index: int) -> None:
        """``kill -9`` a peer and wait until it is gone."""
        peer = self.peers[index]
        pid = peer.pid
        if pid is None:
            raise RuntimeError(f"peer{index} is not running before kill injection")
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError as error:
            raise RuntimeError(f"peer{index} exited before kill injection") from error
        deadline = time.monotonic() + 30
        while self.alive(index) and time.monotonic() < deadline:
            time.sleep(0.05)
        if self.alive(index):
            raise RuntimeError(f"peer{index} remained alive after the 30 s kill bound")
        with self.lock:
            self._end_boot(index, "killed")

    def reap_exited(self) -> list[int]:
        """Record peers whose process ended by itself; returns their indices."""
        exited = []
        for peer in self.peers:
            if peer.pid is not None and not self.alive(peer.index):
                with self.lock:
                    self._end_boot(peer.index, "exited:unknown")
                exited.append(peer.index)
        return exited

    def stop_all(self) -> None:
        """Orderly stop (SIGTERM, then SIGKILL after 20 s) and move the last logs aside."""
        for peer in self.peers:
            if peer.pid is not None and self.alive(peer.index):
                try:
                    os.kill(peer.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
        deadline = time.monotonic() + 20
        while any(peer.pid is not None and self.alive(peer.index) for peer in self.peers):
            if time.monotonic() > deadline:
                for peer in self.peers:
                    if peer.pid is not None and self.alive(peer.index):
                        os.kill(peer.pid, signal.SIGKILL)
                break
            time.sleep(0.1)
        for peer in self.peers:
            if peer.pid is not None:
                with self.lock:
                    self._end_boot(peer.index, "stopped")
            if peer.boot >= 0:
                self._rotate_log(peer.index, peer.boot)

    def fee_asset_id(self) -> str:
        """The fee asset of the network: ``[nexus.fees] fee_asset_id`` of a peer config, or the
        asset the generated faucet dispenses (``[torii.faucet] asset_definition_id``), which
        kagami sets to the fee asset."""
        text = self.config(0).read_text()
        for section, key in (("nexus.fees", "fee_asset_id"), ("torii.faucet", "asset_definition_id")):
            value = toml_string_value(text, section, key)
            if value:
                return value
        raise RuntimeError(f"{self.config(0)} names no fee asset ([nexus.fees] fee_asset_id or [torii.faucet])")

    def _cli_output(self, config: Path, arguments: list[str], timeout: float) -> str:
        result = subprocess.run(
            [str(self.bins["iroha"]), "--config", str(config), *arguments],
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"iroha {' '.join(arguments[:3])} failed ({result.returncode}): "
                + (result.stdout + result.stderr).strip()[-600:]
            )
        return result.stdout

    def fund_load_account(self, quantity: str) -> dict[str, str]:
        """Mint ``quantity`` of the fee asset to the load's account (the generated client),
        signed by the genesis account, which registered the fee asset in genesis and so may
        mint it; returns what was minted to whom.

        The genesis key pair (``genesis.public_key``, ``genesis.private_key`` of the network
        directory) signs through an owner-only copy of the client config.
        """
        client = self.client_config(0)
        public_key = toml_string_value(client.read_text(), "account", "public_key")
        if not public_key:
            raise RuntimeError(f"{client} has no [account] public_key")
        account = self._cli_output(client, ["tools", "address", "convert", public_key], 60).strip().splitlines()[-1]
        asset = self.fee_asset_id()
        funder = self.run_dir / "clients" / "funder.toml"
        text = client.read_text()
        for key, source in (("public_key", "genesis.public_key"), ("private_key", "genesis.private_key")):
            value = (self.net_dir / source).read_text().strip()
            text = set_toml_keys(text, "account", {key: toml_string(value)})
        descriptor = os.open(funder, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w") as handle:
            handle.write(text)
        self._cli_output(
            funder,
            ["ledger", "asset", "mint", "--definition", asset, "--account", account, "--quantity", quantity, "--fee-payer", "authority"],
            300,
        )
        return {"account": account, "asset": asset, "quantity": quantity}

    def kill_everything(self) -> None:
        """Last-resort cleanup: SIGKILL every known peer process."""
        for peer in self.peers:
            if peer.pid is not None:
                try:
                    os.kill(peer.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass


def http_json(url: str, timeout: float = 3.0) -> Optional[dict[str, Any]]:
    """GET ``url`` as JSON, ``None`` on any failure."""
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        return None
    return payload if isinstance(payload, dict) else None


# ---------------------------------------------------------------------------------------------
# Load
# ---------------------------------------------------------------------------------------------

_SUBMITTED_RE = re.compile(r"Submitted\s+(\d+)\s*/\s*(\d+)\s+ping transactions", re.IGNORECASE)


def parse_submitted(output: str) -> Optional[tuple[int, int]]:
    """``(submitted, attempted)`` of a batch ``iroha tx ping`` run."""
    found = None
    for match in _SUBMITTED_RE.finditer(output or ""):
        found = (int(match.group(1)), int(match.group(2)))
    return found


class LoadGenerator(threading.Thread):
    """Offers ``tps`` Log transactions per second through the CLI, rotating over live peers,
    probes commit latency and samples the committed-transaction counters."""

    def __init__(self, net: Localnet, tps: float, probe_interval_s: float, record_path: Path, fee_payer: str = "authority") -> None:
        super().__init__(name="sumeragi-soak-load", daemon=True)
        self.net = net
        self.fee_payer = fee_payer
        self.tps = tps
        self.probe_interval_s = probe_interval_s
        self.record_path = record_path
        self.stop_event = threading.Event()
        self.submitted = 0
        self.attempted = 0
        self.failures = 0
        self.samples: list[dict[str, Any]] = []
        self.probes: list[dict[str, Any]] = []
        self.cursor = 0
        self.sequence = 0
        self.lock = threading.Lock()

    def live_peers(self) -> list[int]:
        """Peers whose process runs."""
        return [peer.index for peer in self.net.peers if peer.pid is not None and self.net.alive(peer.index)]

    def next_peer(self) -> Optional[int]:
        """Round robin over live peers."""
        peers = self.live_peers()
        if not peers:
            return None
        self.cursor = (self.cursor + 1) % len(peers)
        return peers[self.cursor]

    def _cli(self, index: int, arguments: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        command = [str(self.net.bins["iroha"]), "--config", str(self.net.client_config(index)), *arguments]
        return subprocess.run(command, capture_output=True, text=True, check=False, timeout=timeout)

    def submit_batch(self) -> None:
        """One batch of pings without waiting for commits."""
        index = self.next_peer()
        if index is None:
            return
        count = max(1, round(self.tps))
        self.sequence += 1
        try:
            result = self._cli(
                index,
                ["tx", "--fee-payer", self.fee_payer, "ping", "--msg", f"soak-{self.sequence}", "--count", str(count), "--parallel", str(min(count, 8)), "--no-wait"],
                timeout=60,
            )
        except subprocess.TimeoutExpired:
            with self.lock:
                self.failures += 1
                self.attempted += count
            return
        parsed = parse_submitted(result.stdout + result.stderr)
        with self.lock:
            if parsed is None:
                self.failures += 1
                self.attempted += count
            else:
                self.submitted += parsed[0]
                self.attempted += parsed[1]

    def probe(self) -> None:
        """Submit one ping and wait for its commit; the wall time is the latency sample."""
        index = self.next_peer()
        if index is None:
            return
        self.sequence += 1
        start = now_ms()
        try:
            result = self._cli(index, ["tx", "--fee-payer", self.fee_payer, "ping", "--msg", f"soak-probe-{self.sequence}"], timeout=120)
            ok = result.returncode == 0
        except subprocess.TimeoutExpired:
            ok = False
        with self.lock:
            self.probes.append({"start_ms": start, "end_ms": now_ms(), "ok": ok, "peer": index})

    def sample(self) -> None:
        """Committed-transaction counters of every live peer (Torii ``/status``)."""
        for index in self.live_peers():
            status = http_json(f"http://127.0.0.1:{self.net.api_port(index)}/status")
            if status is None or "txs_approved" not in status:
                continue
            with self.lock:
                self.samples.append(
                    {
                        "ts_ms": now_ms(),
                        "node": self.net.node(index),
                        "boot": self.net.peers[index].boot,
                        "txs_approved": int(status["txs_approved"]),
                    }
                )

    def run(self) -> None:
        """Load until stopped."""
        probe_thread = threading.Thread(target=self._probe_loop, name="sumeragi-soak-probe", daemon=True)
        probe_thread.start()
        next_sample = 0.0
        while not self.stop_event.is_set():
            started = time.monotonic()
            self.submit_batch()
            if started >= next_sample:
                self.sample()
                next_sample = started + 5.0
            self.stop_event.wait(max(0.0, 1.0 - (time.monotonic() - started)))
        probe_thread.join(timeout=150)
        self.sample()
        self.write()

    def _probe_loop(self) -> None:
        while not self.stop_event.wait(self.probe_interval_s):
            self.probe()

    def write(self) -> None:
        """Write ``load.json``."""
        with self.lock:
            record = {
                "submitted": self.submitted,
                "attempted": self.attempted,
                "failed_batches": self.failures,
                "offered_tps": self.tps,
                "samples": list(self.samples),
                "probes": list(self.probes),
            }
        self.record_path.write_text(json.dumps(record, indent=2))


# ---------------------------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------------------------


@dataclass
class Options:
    """Resolved options of a run."""

    duration_s: float
    warmup_s: float
    final_quiet_s: float
    fault_window: tuple[float, float]
    fault_gap: tuple[float, float]
    thresholds: logs.Thresholds
    load_tps: float
    disk_size_mb: int
    storage_budget_mb: int
    fund: str
    kinds: tuple[str, ...]
    net_mode: str
    seed: int
    validators: int
    loss: tuple[float, float]
    max_kill: int
    disk_node: Optional[int]
    extra: dict[str, Any] = field(default_factory=dict)


def resolve_options(args: argparse.Namespace) -> Options:
    """Apply the profile and derive the thresholds."""
    profile = PROFILES[args.profile]
    duration = args.duration if args.duration is not None else parse_duration(profile["duration"])
    warmup = args.warmup if args.warmup is not None else parse_duration(profile["warmup"])
    final_quiet = args.final_quiet if args.final_quiet is not None else parse_duration(profile["final_quiet"])
    kinds = tuple(kind.strip() for kind in args.faults.split(",") if kind.strip() and kind.strip() != "none")
    for kind in kinds:
        if kind not in faults.FAULT_KINDS:
            raise SystemExit(f"unknown fault kind {kind!r} (expected kill, disk, net or none)")
    net_mode = args.net_mode
    if net_mode == "auto":
        net_mode = "netem" if sys.platform.startswith("linux") and shutil.which("tc") else "proxy"
    if net_mode == "off":
        kinds = tuple(kind for kind in kinds if kind != "net")
    if net_mode == "netem" and not sys.platform.startswith("linux"):
        raise SystemExit("--net-mode netem needs Linux (tc netem in a network namespace); use --net-mode proxy")
    seed = args.seed if args.seed is not None else random.SystemRandom().randrange(1, 2**31)
    if args.live_bound is not None:
        live_bound_ms = args.live_bound * 1000.0
    elif profile["live_bound"] is not None:
        live_bound_ms = parse_duration(profile["live_bound"]) * 1000.0
    else:
        live_bound_ms = logs.live_bound_ms(logs.LiveBoundParams(n=args.validators, lag_heights=args.live_lag_heights))
    # O-LIVE judges only a fault-free interval at least as long as its bound: the final one
    # (the whole run without faults) must be, or a stall could never fail the run.
    judged_s = final_quiet if kinds else duration
    if judged_s * 1000.0 < live_bound_ms:
        raise SystemExit(
            f"the final fault-free interval ({judged_s:.0f} s) is shorter than the O-LIVE bound "
            f"({live_bound_ms / 1000.0:.0f} s), so O-LIVE could never judge a stall; "
            "raise --final-quiet (--duration without faults) or lower --live-bound"
        )
    load_tps = args.load_tps if args.load_tps is not None else profile["load_tps"]
    min_tps = args.min_tps if args.min_tps is not None else round(load_tps * profile["min_tps_ratio"], 3)
    thresholds = logs.Thresholds(
        live_bound_ms=live_bound_ms,
        max_gap_p99_ms=args.max_gap_p99_ms if args.max_gap_p99_ms is not None else profile["max_gap_p99_ms"],
        max_gap_ms=args.max_gap_ms if args.max_gap_ms is not None else profile["max_gap_ms"],
        max_latency_p99_ms=args.max_latency_p99_ms if args.max_latency_p99_ms is not None else profile["max_latency_p99_ms"],
        min_tps=min_tps,
        warmup_heights=args.warmup_heights if args.warmup_heights is not None else profile["warmup_heights"],
    )
    disk_size_mb = args.disk_size_mb if args.disk_size_mb is not None else profile["disk_size_mb"]
    storage_budget_mb = (
        args.storage_budget_mb if args.storage_budget_mb is not None else profile["storage_budget_mb"]
    )
    if storage_budget_mb <= 0 or disk_size_mb <= 0:
        raise SystemExit("--storage-budget-mb and --disk-size-mb must be positive")
    if "disk" in kinds and storage_budget_mb >= disk_size_mb:
        # The disk-full peer must reach ENOSPC only when a disk fault fills its volume, never
        # by growing within its storage budget.
        raise SystemExit(
            f"--storage-budget-mb ({storage_budget_mb}) must be below --disk-size-mb ({disk_size_mb})"
        )
    fund = str(args.fund).strip()
    if not re.fullmatch(r"\d+(\.\d+)?", fund):
        raise SystemExit(f"--fund must be a non-negative decimal quantity, got {args.fund!r}")
    f = faults.max_faulty(args.validators)
    disk_node = args.disk_node if args.disk_node is not None else args.validators - 1
    if not 0 <= disk_node < args.validators:
        raise SystemExit(f"--disk-node must be a peer index below {args.validators}")
    return Options(
        duration_s=duration,
        warmup_s=warmup,
        final_quiet_s=final_quiet,
        fault_window=args.fault_window or profile["fault_window"],
        fault_gap=args.fault_gap or profile["fault_gap"],
        thresholds=thresholds,
        load_tps=load_tps,
        disk_size_mb=disk_size_mb,
        storage_budget_mb=storage_budget_mb,
        fund=fund,
        kinds=kinds,
        net_mode=net_mode,
        seed=seed,
        validators=args.validators,
        loss=args.loss,
        max_kill=min(args.max_kill if args.max_kill is not None else 1, f),
        disk_node=disk_node if "disk" in kinds else None,
        extra={
            "reset_ratio": args.reset_ratio,
            "probe_interval_s": args.probe_interval,
            "profile": args.profile,
            "fee_payer": args.fee_payer,
        },
    )


def thresholds_json(thresholds: logs.Thresholds) -> dict[str, Any]:
    """Thresholds for ``run.json``."""
    return {
        "live_bound_ms": thresholds.live_bound_ms,
        "max_gap_p99_ms": thresholds.max_gap_p99_ms,
        "max_gap_ms": thresholds.max_gap_ms,
        "max_latency_p99_ms": thresholds.max_latency_p99_ms,
        "min_tps": thresholds.min_tps,
        "warmup_heights": thresholds.warmup_heights,
    }


def resolve_bins(bin_dir: Optional[Path]) -> dict[str, Path]:
    """Paths of iroha3d, kagami and iroha."""
    candidates = [bin_dir] if bin_dir else [REPO_ROOT / "target" / "release", REPO_ROOT / "target" / "debug"]
    for directory in candidates:
        bins = {name: (directory / name).resolve() for name in ("iroha3d", "kagami", "iroha")}
        if all(path.is_file() and os.access(path, os.X_OK) for path in bins.values()):
            return bins
    raise SystemExit(
        "iroha3d, kagami and iroha not found in "
        + ", ".join(str(directory) for directory in candidates)
        + "; build them with `cargo build --release -p irohad --bin iroha3d -p iroha_kagami --bin kagami -p iroha_cli --bin iroha` or pass --bin-dir"
    )


def enter_namespace_if_needed(options: Options, argv: Sequence[str]) -> None:
    """On Linux, re-run inside a fresh user, network and mount namespace for netem and tmpfs."""
    if not sys.platform.startswith("linux") or os.environ.get(NAMESPACE_ENV) == "1":
        return
    if options.net_mode != "netem" and "disk" not in options.kinds:
        return
    unshare = shutil.which("unshare")
    if unshare is None:
        raise SystemExit("netem and disk faults on Linux need `unshare` (util-linux)")
    env = dict(os.environ)
    env[NAMESPACE_ENV] = "1"
    command = [unshare, "--user", "--map-root-user", "--net", "--mount", "--fork", "--kill-child", sys.executable, *argv]
    os.execvpe(unshare, command, env)


def require_fault_plan(plan: Sequence[faults.Fault], options: Options) -> None:
    """Refuse invalid or incomplete requested fault coverage before startup."""
    previous_end = options.warmup_s
    for fault in plan:
        if (
            fault.kind not in options.kinds
            or any(node not in range(options.validators) for node in fault.nodes)
            or len(set(fault.nodes)) != len(fault.nodes)
            or (fault.kind == "kill" and not 1 <= len(fault.nodes) <= options.max_kill)
            or (fault.kind == "disk" and fault.nodes != (options.disk_node,))
            or (fault.kind == "net" and bool(fault.nodes))
            or not all(math.isfinite(value) for value in (fault.start_s, fault.duration_s, fault.end_s))
            or fault.duration_s <= 0
            or fault.start_s < previous_end
            or fault.end_s + options.final_quiet_s > options.duration_s
        ):
            raise SystemExit("invalid fault plan: kind or positive ordered timing outside the configured run")
        previous_end = fault.end_s
    missing = logs.missing_requested_faults(options.kinds, (fault.kind for fault in plan))
    if missing:
        raise SystemExit(
            "fault plan does not cover requested kinds within the configured duration: "
            + ", ".join(missing)
        )


def run_soak(args: argparse.Namespace, argv: Sequence[str]) -> int:
    """Generate, run, inject and judge."""
    options = resolve_options(args)
    rng = random.Random(options.seed)
    plan = faults.plan_faults(
        faults.PlanOptions(
            duration_s=options.duration_s,
            warmup_s=options.warmup_s,
            final_quiet_s=options.final_quiet_s,
            kinds=options.kinds,
            validators=options.validators,
            disk_node=options.disk_node,
            gap_s=options.fault_gap,
            window_s=options.fault_window,
            loss=options.loss,
            max_kill=options.max_kill,
        ),
        rng,
    )
    require_fault_plan(plan, options)
    if args.seed is None:
        # Record the drawn seed so that a namespace re-execution keeps it.
        argv = [*argv, "--seed", str(options.seed)]
    enter_namespace_if_needed(options, argv)
    if args.out is None:
        raise SystemExit("--out is required")
    run_dir = args.out.resolve()
    if run_dir.exists() and any(run_dir.iterdir()):
        raise SystemExit(f"{run_dir} is not empty")
    run_dir.mkdir(parents=True, exist_ok=True)
    bins = resolve_bins(args.bin_dir)
    base_proxy = args.base_proxy_port if args.base_proxy_port is not None else args.base_p2p_port + 100
    ports = [args.base_api_port + index for index in range(options.validators)]
    ports += [args.base_p2p_port + index for index in range(options.validators)]
    if options.net_mode == "proxy" and "net" in options.kinds:
        ports += [base_proxy + index for index in range(options.validators)]
    if len(set(ports)) != len(ports):
        raise SystemExit("the Torii, P2P and proxy port ranges overlap")
    if sys.platform.startswith("linux") and os.environ.get(NAMESPACE_ENV) == "1":
        subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    busy = [port for port in ports if not port_free(port)]
    if busy:
        raise SystemExit(f"ports already in use: {busy}")
    run_record: dict[str, Any] = {
        "seed": options.seed,
        "validators": options.validators,
        "faults": list(options.kinds),
        "net_mode": options.net_mode,
        "platform": sys.platform,
        "duration_s": options.duration_s,
        "loss": list(options.loss),
        "load_tps": options.load_tps,
        "storage_budget_mb": options.storage_budget_mb,
        "fund": options.fund,
        "bins": {name: str(path) for name, path in bins.items()},
        "thresholds": thresholds_json(options.thresholds),
        "plan": [dataclasses.asdict(fault) for fault in plan],
        **options.extra,
    }
    (run_dir / "run.json").write_text(json.dumps(run_record, indent=2))
    print(f"sumeragi soak: {options.validators} validators, {options.duration_s:.0f} s, seed {options.seed}, "
          f"faults {','.join(options.kinds) or 'none'} ({len(plan)} windows), net mode {options.net_mode}, out {run_dir}")
    net = Localnet(run_dir, bins, options.validators, options.seed, args.base_api_port, args.base_p2p_port)
    conditions = faults.ConditionBox()
    proxy: Optional[faults.ProxyNetwork] = None
    netem: Optional[faults.Netem] = None
    volume: Optional[faults.DiskVolume] = None
    load: Optional[LoadGenerator] = None
    windows: list[dict[str, Any]] = []
    start_ms = end_ms = now_ms()
    try:
        net.generate()
        proxy_ports = None
        if "net" in options.kinds and options.net_mode == "proxy":
            proxy_ports = {index: base_proxy + index for index in range(options.validators)}
            proxy = faults.ProxyNetwork(
                [("127.0.0.1", proxy_ports[index], "127.0.0.1", net.p2p_port(index)) for index in range(options.validators)],
                conditions,
                options.seed,
            )
            proxy.start()
        if "net" in options.kinds and options.net_mode == "netem":
            netem = faults.Netem([net.p2p_port(index) for index in range(options.validators)])
            netem.setup()
        net.patch_configs(proxy_ports, options.storage_budget_mb * 1024 * 1024)
        if options.disk_node is not None:
            net.move_kura_into_state(options.disk_node)
            volume = faults.DiskVolume(net.state_dir(options.disk_node), run_dir, options.disk_size_mb)
            volume.mount()
        for index in range(options.validators):
            net.start(index)
        wait_for_torii(net, timeout_s=300)
        if float(options.fund) > 0:
            run_record["funding"] = net.fund_load_account(options.fund)
            print(f"funded the load account with {options.fund} of {run_record['funding']['asset']}")
        load = LoadGenerator(
            net,
            options.load_tps,
            float(options.extra["probe_interval_s"]),
            run_dir / "load.json",
            str(options.extra["fee_payer"]),
        )
        start_ms = now_ms()
        load.start()
        started = time.monotonic()
        for fault in plan:
            supervise_until(net, started + fault.start_s, set())
            windows.append(run_fault(fault, net, started, rng, options, conditions, netem, volume))
        supervise_until(net, started + options.duration_s, set())
        end_ms = now_ms()
    except KeyboardInterrupt:
        end_ms = now_ms()
        print("interrupted; judging what ran", file=sys.stderr)
    except Exception as error:  # a harness failure, not an oracle verdict
        end_ms = now_ms()
        print(f"sumeragi soak harness error: {error}", file=sys.stderr)
        (run_dir / "harness-error.txt").write_text(str(error))
        cleanup(net, load, proxy, netem, volume, run_record, run_dir, args.keep_state)
        return EXIT_HARNESS
    cleanup(net, load, proxy, netem, volume, run_record, run_dir, args.keep_state)
    timeline = logs.Timeline(
        start_ms=start_ms,
        end_ms=end_ms,
        nodes=tuple(net.node(index) for index in range(options.validators)),
        windows=tuple(
            logs.Window(window["start_ms"], window["end_ms"], window["kind"], tuple(window["nodes"]))
            for window in windows
        ),
        boots=tuple(logs.Boot(boot.node, boot.index, boot.start_ms, boot.end_ms, boot.ended) for boot in net.boots),
    )
    (run_dir / "timeline.json").write_text(json.dumps(timeline.to_json(), indent=2))
    return judge(run_dir)


def torii_ready(port: int) -> bool:
    """Whether Torii at ``port`` answers ``/health`` with a success status."""
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=3) as response:
            return 200 <= response.status < 300
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        return False


STARTUP_RESTARTS = 3


def wait_for_torii(net: Localnet, timeout_s: float, max_restarts: int = STARTUP_RESTARTS) -> None:
    """Wait until every peer's Torii answers ``/health``.

    A peer that exits while starting is started again, at most ``max_restarts`` times: its
    exited boot stays in the timeline, where O-LIVE reports it as an unexpected exit, and the run
    goes on to judge consensus. A peer that keeps exiting is a harness error.
    """
    deadline = time.monotonic() + timeout_s
    pending = set(range(net.validators))
    restarts = dict.fromkeys(pending, 0)
    while pending:
        for index in net.reap_exited():
            log = net.log_dir / net.node(index) / f"boot{net.peers[index].boot}.log"
            if restarts[index] >= max_restarts:
                raise RuntimeError(f"peer{index} exited during startup {restarts[index] + 1} times; see {log}")
            restarts[index] += 1
            print(f"peer{index} exited during startup; starting it again (see {log})", file=sys.stderr)
            net.start(index)
            pending.add(index)
        for index in sorted(pending):
            if torii_ready(net.api_port(index)):
                pending.discard(index)
        if pending and time.monotonic() > deadline:
            raise RuntimeError(f"peers {sorted(pending)} did not answer /health within {timeout_s:.0f} s")
        time.sleep(1.0)


def supervise_until(net: Localnet, deadline: float, tolerated: set[int]) -> None:
    """Until ``deadline`` (monotonic), restart peers that exited by themselves.

    A peer in ``tolerated`` (its disk is full) stays down until its window heals; any other
    exit is recorded (O-LIVE judges it) and the peer is restarted at once.
    """
    while True:
        remaining = deadline - time.monotonic()
        for index in net.reap_exited():
            print(f"peer{index} exited by itself", file=sys.stderr)
            if index not in tolerated:
                net.start(index)
        if remaining <= 0:
            return
        time.sleep(min(1.0, remaining))


def run_fault(
    fault: faults.Fault,
    net: Localnet,
    started: float,
    rng: random.Random,
    options: Options,
    conditions: faults.ConditionBox,
    netem: Optional[faults.Netem],
    volume: Optional[faults.DiskVolume],
) -> dict[str, Any]:
    """Inject one fault window and heal it; returns the window for ``timeline.json``."""
    window_start = now_ms()
    names = [net.node(index) for index in fault.nodes]
    print(f"[{time.strftime('%H:%M:%S')}] fault {fault.kind} {names or ''} loss {fault.loss:.2f} for {fault.duration_s:.0f} s")
    end = started + fault.end_s
    if time.monotonic() >= end:
        raise RuntimeError(f"fault window {fault.kind} expired before injection")
    tolerated: set[int] = set()
    if fault.kind == "kill":
        for index in fault.nodes:
            net.kill(index)
        if time.monotonic() >= end:
            raise RuntimeError(f"fault window {fault.kind} expired before injection completed")
        tolerated = set(fault.nodes)
        supervise_until(net, end, tolerated)
        for index in fault.nodes:
            if net.peers[index].pid is None:
                net.start(index)
    elif fault.kind == "disk":
        assert volume is not None
        filled = volume.fill()
        print(f"  disk of peer{fault.nodes[0]} filled with {filled // (1024 * 1024)} MiB")
        if time.monotonic() >= end:
            raise RuntimeError(f"fault window {fault.kind} expired before injection completed")
        tolerated = set(fault.nodes)
        supervise_until(net, end, tolerated)
        volume.free()
        for index in fault.nodes:
            if net.peers[index].pid is None:
                net.start(index)
    else:
        base = faults.net_condition(fault.loss, rng, float(options.extra["reset_ratio"]))
        spikes = faults.spike_plan(rng, fault.duration_s)
        current = None
        applied = False
        application_late = False
        while True:
            now = time.monotonic()
            if now >= end:
                break
            offset = now - (started + fault.start_s)
            spike = next((extra for at, length, extra in spikes if at <= offset < at + length), 0.0)
            condition = base.with_spike(spike)
            if condition != current:
                conditions.set(condition)
                if netem is not None:
                    netem.apply(condition)
                current = condition
                if condition != faults.CLEAR:
                    applied = True
                    if time.monotonic() >= end:
                        application_late = True
                        break
            supervise_until(net, min(end, now + 0.25), set())
        conditions.set(faults.CLEAR)
        if netem is not None:
            netem.apply(faults.CLEAR)
        if application_late:
            raise RuntimeError("network fault condition application completed at or after its endpoint")
        if not applied:
            raise RuntimeError("network fault window ended without applying a non-clear condition")
    return {"start_ms": window_start, "end_ms": now_ms(), "kind": fault.kind, "nodes": names}


def cleanup(
    net: Localnet,
    load: Optional[LoadGenerator],
    proxy: Optional[faults.ProxyNetwork],
    netem: Optional[faults.Netem],
    volume: Optional[faults.DiskVolume],
    run_record: dict[str, Any],
    run_dir: Path,
    keep_state: bool,
) -> None:
    """Stop the load, the peers and the fault injectors; keep logs, drop state unless asked."""
    if load is not None:
        load.stop_event.set()
        load.join(timeout=200)
        if load.is_alive():
            load.write()
    try:
        net.stop_all()
    finally:
        net.kill_everything()
    if proxy is not None:
        run_record["proxy"] = proxy.stats.to_json()
        proxy.stop()
    if netem is not None:
        netem.teardown()
    if volume is not None:
        try:
            volume.free()
        finally:
            volume.unmount()
    (run_dir / "run.json").write_text(json.dumps(run_record, indent=2))
    if not keep_state:
        for durable in ("state", "storage"):
            shutil.rmtree(net.net_dir / durable, ignore_errors=True)


def judge(run_dir: Path) -> int:
    """Compute the verdict of a finished run, write ``verdict.json``, print a summary."""
    run = json.loads((run_dir / "run.json").read_text())
    timeline = logs.Timeline.from_json(json.loads((run_dir / "timeline.json").read_text()))
    load_path = run_dir / "load.json"
    load = logs.LoadRecord.from_json(json.loads(load_path.read_text())) if load_path.exists() else None
    thresholds = logs.Thresholds(**run["thresholds"])
    # Streamed through the incremental oracles: a long diagnostic's logs never sit in memory whole.
    analysis = logs.analyze_logs(run_dir / "logs")
    verdict = logs.build_verdict(
        analysis,
        timeline,
        thresholds,
        load,
        {key: run[key] for key in ("seed", "validators", "faults", "net_mode", "platform", "duration_s", "load_tps") if key in run},
    )
    if "proxy" in run:
        verdict["proxy"] = run["proxy"]
    (run_dir / "verdict.json").write_text(json.dumps(verdict, indent=2))
    summary = {name: ("ok" if entry["ok"] else f"{entry['violation_count']} violation(s)") for name, entry in verdict["oracles"].items()}
    print(json.dumps({"ok": verdict["ok"], "oracles": summary, "harness": verdict["harness"], "verdict": str(run_dir / "verdict.json")}, indent=2))
    return EXIT_OK if verdict["ok"] else EXIT_VIOLATION


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point."""
    argv = list(sys.argv[1:] if argv is None else argv)
    # Progress lines reach a CI log or a redirected file as they happen, not in 8 KiB blocks.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)
    args = build_parser().parse_args(argv)
    if args.analyze is not None:
        return judge(args.analyze.resolve())
    return run_soak(args, [str(Path(__file__).resolve()), *argv])


if __name__ == "__main__":
    sys.exit(main())
