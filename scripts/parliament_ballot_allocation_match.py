#!/usr/bin/env python3
"""Compare observed routed allocation events with a pinned source grammar.

Python 3.11+, adjacent parliament_ballot_arena_model.py. No environment variables,
builds, network or production changes. Inputs are explicit JSON lists of actual
[operation, arena-relative offset, size, alignment] records and source events.
The reader/runner separately establishes binary provenance and complete capture.
Only the observed finite stream is checked; universal correspondence stays false.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from parliament_ballot_arena_model import Buddy, HEAP_BYTES, TraceError


def compare(records: list, grammar: list) -> dict:
    """Require exact layouts, allocator offsets, lifetime order and full consumption."""
    if not isinstance(records, list) or not isinstance(grammar, list):
        raise ValueError("records and grammar must be lists")
    if len(records) > 524288:
        raise ValueError("observed stream exceeds diagnostic capacity")
    for record in records:
        if (not isinstance(record, (list, tuple)) or len(record) != 4
                or any(type(value) is not int or not 0 <= value < 1 << 64 for value in record)
                or record[0] not in (1, 2) or not 0 < record[2] <= HEAP_BYTES
                or record[3] == 0 or record[3] & (record[3] - 1)
                or record[1] >= HEAP_BYTES or record[2] > HEAP_BYTES - record[1]):
            raise ValueError("invalid observed allocator record")
    model = Buddy()
    index = 0
    repeats = []

    def consume(event: dict) -> None:
        nonlocal index
        if not isinstance(event, dict) or event.get("op") not in ("alloc", "free"):
            raise ValueError("only concrete allocation/free events can be consumed")
        if event["op"] == "alloc":
            offset = model.allocate(event["id"], event["size"], event["align"])
            expected = [1, offset, event["size"], event["align"]]
        else:
            if event["id"] not in model.live:
                raise ValueError("grammar releases an unknown allocation")
            live = model.live[event["id"]]
            expected = [2, live.offset, live.size, live.alignment]
            model.release(event["id"])
        if index >= len(records) or list(records[index]) != expected:
            actual = records[index] if index < len(records) else None
            raise ValueError(f"event {index} ({event['id']}): expected {expected}, observed {actual}")
        index += 1

    for event in grammar:
        if not isinstance(event, dict):
            raise ValueError("grammar event must be an object")
        if event.get("op") != "repeat_restoring":
            consume(event)
            continue
        minimum, maximum = event.get("min"), event.get("max")
        body = event.get("body")
        if (type(minimum) is not int or type(maximum) is not int or not 0 <= minimum <= maximum <= 524288
                or not isinstance(body, list) or len(body) != 2
                or not all(isinstance(item, dict) for item in body)
                or body[0].get("op") != "alloc" or body[1].get("op") != "free"
                or body[0].get("id") != body[1].get("id")):
            raise ValueError("unsupported restoring repetition grammar")
        # The frozen grammar has a single temporary provider per iteration.
        # A later concrete event with the same prefix would be ambiguous: fail
        # on any mismatch rather than search for a convenient interpretation.
        before = model.state()
        count = 0
        while count < maximum and index < len(records):
            observed = records[index]
            if (observed[0], observed[2], observed[3]) != (1, body[0].get("size"), body[0].get("align")):
                break
            consume(body[0])
            consume(body[1])
            if model.state() != before:
                raise ValueError("provider repetition did not restore allocator state")
            count += 1
        if count < minimum:
            raise ValueError(f"provider repetition below minimum: {event.get('id')}: {count} < {minimum}")
        repeats.append({"id": event.get("id"), "observed": count, "min": minimum, "max": maximum})
    if index != len(records):
        raise ValueError(f"unmatched observed events after {index}")
    if model.live:
        raise ValueError("matched stream retained allocations")
    return {"events_matched": index, "allocations_observed": model.allocations,
            "peak_requested_bytes": model.peak_requested, "peak_block_bytes": model.peak_blocks,
            "peak_live_objects": model.peak_objects, "provider_repetitions": repeats,
            "finite_ordered_stream_match": True, "complete_allocation_correspondence": False,
            "complete_workspace_certificate": False, "profile_qualified": False}


def main() -> int:
    """Compare explicit files and refuse malformed or mismatched streams."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--records", required=True, type=Path)
    parser.add_argument("--grammar", required=True, type=Path)
    args = parser.parse_args()
    try:
        report = compare(json.loads(args.records.read_text()), json.loads(args.grammar.read_text()))
        print(json.dumps(report, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError, TraceError) as error:
        print(json.dumps({"failure": str(error), "finite_ordered_stream_match": False, "profile_qualified": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
