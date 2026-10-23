#!/usr/bin/env python3
"""Check or reproduce the small official NIST ACVP subset used by soranet_pq.

The default is an offline digest check. Reproduction verifies five upstream
source digests before selecting unchanged groups/cases. No Iroha implementation
is executed and no expected cryptographic output is computed here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import urllib.request

REVISION = '975de31eb83d87039ec88934fdc47d8c312b892d'
FIXTURE_SHA256 = 'd9d0a4d7e15e07df887d8fd068e9cea86d2580ec179b47fa5b04cb4a00815860'
SOURCE_SHA256 = {'ML-KEM-keyGen-FIPS203': 'd7a62a2c3476957f56dd8d24f9004ea6776ccfe995ffe71a65bb9506dc9c7b1b',
 'ML-KEM-encapDecap-FIPS203-tr1': '5e88fbd351dc2915b2ab399f5dffd269e1cdbdd0186103ab0e90b374cf592187',
 'ML-DSA-keyGen-FIPS204': 'e67ee6540d40e11506c3c4e3b1f79fc1cefcd49820db99fc61f87cc8ba463baf',
 'ML-DSA-sigGen-FIPS204-tr1': 'b61576c765b1eb0e6a667a67a68380df944592be8740f9c020c9ea5a89136f18',
 'ML-DSA-sigVer-FIPS204': '47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437'}
SELECTED_CASES = {'ML-KEM-keyGen-FIPS203': {1: [1], 2: [26], 3: [51]},
 'ML-KEM-encapDecap-FIPS203-tr1': {1: [1],
                                   2: [26],
                                   3: [51],
                                   5: [86, 88],
                                   7: [106, 109],
                                   9: [126, 127],
                                   10: [136, 137],
                                   11: [146, 147],
                                   12: [156, 157],
                                   13: [166, 171],
                                   14: [176, 177],
                                   15: [186, 187]},
 'ML-DSA-keyGen-FIPS204': {1: [1], 2: [26], 3: [51]},
 'ML-DSA-sigGen-FIPS204-tr1': {27: [399, 403, 405], 31: [452, 462], 35: [512, 513, 521]},
 'ML-DSA-sigVer-FIPS204': {1: [1, 2, 3, 5, 7],
                           3: [31, 32, 33, 34, 35],
                           5: [61, 63, 64, 65, 72]}}
FIXTURE = Path(__file__).resolve().parents[1] / "crates/soranet_pq/tests/fixtures/acvp/vectors.json"


def project(document: dict, selection: dict[int, list[int]]) -> dict:
    """Retain exactly the selected original groups and complete test objects."""
    groups = []
    found_groups = []
    for group in document["testGroups"]:
        group_id = group["tgId"]
        if group_id not in selection:
            continue
        selected = selection[group_id]
        cases = [case for case in group["tests"] if case["tcId"] in selected]
        if [case["tcId"] for case in cases] != selected:
            raise ValueError(f"missing, duplicate or reordered selected cases in group {group_id}")
        groups.append({**group, "tests": cases})
        found_groups.append(group_id)
    if found_groups != list(selection):
        raise ValueError("missing, duplicate or reordered selected groups")
    return {**document, "testGroups": groups}


def extract(sources: dict[str, bytes]) -> bytes:
    """Authenticate upstream bytes, then copy the pinned cases without transformation."""
    if sources.keys() != SOURCE_SHA256.keys():
        raise ValueError("source set must contain exactly the five pinned NIST files")
    sets = []
    for name, digest in SOURCE_SHA256.items():
        raw = sources[name]
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError(f"upstream SHA-256 mismatch: {name}")
        document = json.loads(raw)
        selected = project(document, SELECTED_CASES[name])
        sets.append({"source": name, "source_sha256": digest, **selected})
    fixture = {"upstream_revision": REVISION, "vector_sets": sets}
    return (json.dumps(fixture, indent=2) + "\n").encode("utf-8")


def check_fixture(raw: bytes) -> None:
    """Refuse any fixture edit unless its separately reviewed pin also changes."""
    if hashlib.sha256(raw).hexdigest() != FIXTURE_SHA256:
        raise ValueError("tracked ACVP subset SHA-256 mismatch")


def load_sources(directory: Path, download: bool) -> dict[str, bytes]:
    """Read a caller-chosen cache; download only explicit missing pinned sources."""
    if download:
        directory.mkdir(parents=True, exist_ok=True)
    sources = {}
    for name, digest in SOURCE_SHA256.items():
        path = directory / f"{name}.json"
        if not path.exists() and download:
            url = (
                "https://raw.githubusercontent.com/usnistgov/ACVP-Server/"
                f"{REVISION}/gen-val/json-files/{name}/internalProjection.json"
            )
            with urllib.request.urlopen(url, timeout=60) as response:
                raw = response.read()
            if hashlib.sha256(raw).hexdigest() != digest:
                raise ValueError(f"downloaded SHA-256 mismatch: {name}")
            path.write_bytes(raw)
        sources[name] = path.read_bytes()
    return sources


def main(argv: list[str] | None = None) -> int:
    """Run the offline check, or reproduce from authenticated NIST source files."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, default=FIXTURE)
    parser.add_argument("--source-dir", type=Path, help="directory for pinned upstream JSON files")
    parser.add_argument("--download", action="store_true", help="fetch missing pinned files into --source-dir")
    parser.add_argument("--write", action="store_true", help="write the reproduced subset to --fixture")
    args = parser.parse_args(argv)
    if (args.download or args.write) and args.source_dir is None:
        parser.error("--download and --write require --source-dir")
    try:
        if args.source_dir is not None:
            reproduced = extract(load_sources(args.source_dir, args.download))
            check_fixture(reproduced)
            if args.write:
                args.fixture.write_bytes(reproduced)
            elif args.fixture.read_bytes() != reproduced:
                raise ValueError("tracked fixture differs from authenticated source projection")
        check_fixture(args.fixture.read_bytes())
    except (OSError, ValueError) as error:
        parser.exit(1, f"ACVP subset check failed: {error}\n")
    print(f"ACVP subset verified: 50 cases, 24 groups, revision {REVISION}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
