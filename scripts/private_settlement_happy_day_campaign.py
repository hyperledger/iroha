#!/usr/bin/env python3
"""Validate one real-process SORA Nexus happy-day payment and its retained evidence.

Requires Python 3.11+, the sibling smoke/release validation helpers, and an
owner-only directory emitted by the exact happy-day Rust test. This module
does not build or launch processes. The caller must separately authenticate
source, images, native test completion and process closure. The explicit
happy_day scope includes financial checks, all 16 signed finality proofs,
replay and continuous terminal observations; it makes no restart claim.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import private_settlement_smoke_campaign as shared

TEST_NAME = shared.HAPPY_DAY_TEST_NAME
PROTOCOL = shared.PROTOCOL
EVIDENCE_NAMES = shared.HAPPY_DAY_EVIDENCE_NAMES
RAYON_WORKER_THREADS = shared.RAYON_WORKER_THREADS
PEER_COUNT = shared.PEER_COUNT
RUN_COUNT = shared.RUN_COUNT
CampaignError = shared.CampaignError
artifact_bindings = shared.artifact_bindings
invocation_environment = shared.invocation_environment
sanitized_environment = shared.sanitized_environment
write_json = shared.write_json


def validate_request(value, commit, run):
    """Require a bound happy-day request; a smoke request is a different experiment."""
    return shared.validate_request(value, commit, run, kind="happy_day")


def new_request(commit, run):
    """Create fresh request entropy for the explicitly selected happy-day experiment."""
    return shared.new_request(commit, run, kind="happy_day")


def validate_discovery(output):
    """Require discovery of exactly the happy-day native entrypoint."""
    shared.require(output.strip().splitlines() == [f"{TEST_NAME}: test", "", "1 test, 0 benchmarks"],
                   "exact ignored happy-day test discovery failed")


def terminal_success(output):
    """Require one executed happy-day test with its unique completion marker."""
    return shared.terminal_success(output, kind="happy_day")


def validate_run(path, request, validator_sha):
    """Validate exactly 79 actual artifacts and unchanged live validator identities."""
    return shared.validate_run(path, request, validator_sha, kind="happy_day")


def main():
    """Offer read-only artifact validation; native/source admission remains external."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-directory", type=Path, required=True)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--validator-sha256", required=True)
    args = parser.parse_args()
    request = shared.read_json(args.request)
    validate_request(request, request["commit"], request["run"])
    summary = validate_run(args.run_directory, request, args.validator_sha256)
    sys.stdout.buffer.write(shared.canonical(summary) + b"\n")


if __name__ == "__main__":
    main()
