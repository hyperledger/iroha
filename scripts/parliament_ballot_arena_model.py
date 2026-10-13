#!/usr/bin/env python3
"""Replay source-derived ballot allocation traces against a sparse buddy model.

Python 3.11+, standard library only. No environment variables, builds, network,
or checkout writes. Events describe requested layouts and lifetime order; this
module cannot establish that a trace covers an actual verifier invocation.
The allocator policy is the standalone resource_contract/arena.rs policy:
64-byte minimum blocks, leftmost suitable block, splitting and eager coalescing.
Use --help for a JSON trace diagnostic. This never qualifies production.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Iterable

MIN_BLOCK = 64
HEAP_BYTES = 32 * 1024 * 1024
DEFAULT_ALIGNMENT = 16 * 1024
MAX_EVENT_DEPTH = 32


class TraceError(ValueError):
    """The trace, allocation, or claimed restoring subtrace is invalid."""


def positive_power_of_two(value: int) -> bool:
    """Require a non-bool positive power-of-two integer."""
    return type(value) is int and value > 0 and value & (value - 1) == 0


def block_bytes(size: int, alignment: int) -> int:
    """Round one admitted nonzero Rust allocation layout to its buddy block."""
    if type(size) is not int or size <= 0 or not positive_power_of_two(alignment):
        raise TraceError("allocation requires positive size and power-of-two alignment")
    needed = max(size, alignment, MIN_BLOCK)
    return 1 << (needed - 1).bit_length()


def spatial_admission_bound(heap_bytes: int, requested_block: int,
                            live_blocks: Iterable[int]) -> dict[str, int | bool]:
    """Bound occupied request-sized bins without assuming allocation order.

    Buddy blocks smaller than B intersect exactly one aligned B-bin; blocks
    at least B occupy block/B bins. Summing can double-count shared bins, so
    it is an upper bound. If fewer than heap/B bins can be occupied, at least
    one B-bin is wholly free and eager coalescing makes its node available.
    This is a sufficient condition, never a necessary one. Quota and alignment
    must also be checked separately by the caller.
    """
    blocks = tuple(live_blocks)
    if (not positive_power_of_two(heap_bytes) or heap_bytes < MIN_BLOCK
            or not positive_power_of_two(requested_block)
            or not MIN_BLOCK <= requested_block <= heap_bytes
            or any(not positive_power_of_two(block) or not MIN_BLOCK <= block <= heap_bytes
                   for block in blocks)
            or sum(blocks) > heap_bytes):
        raise TraceError("spatial bound requires valid buddy block sizes")
    bins = heap_bytes // requested_block
    occupied = sum(max(1, block // requested_block) for block in blocks)
    return {"request_sized_bins": bins, "occupied_bins_upper_bound": occupied,
            "free_bins_lower_bound": max(0, bins - occupied),
            "guaranteed_free_block": occupied < bins}


@dataclass(frozen=True)
class Allocation:
    """One live named layout and the block selected for it."""

    offset: int
    size: int
    alignment: int
    block: int


class Buddy:
    """Sparse representation of the same canonical free topology as Arena.

    Each free block is present at its maximal coalesced order. Selecting the
    lowest start address among all sufficiently large free blocks is equivalent
    to the Rust tree's left-first descent using each subtree's largest order.
    Existing allocations may survive a restoring subtrace; their IDs, layouts,
    offsets, and the entire free topology must remain identical afterward.
    """

    def __init__(self, heap_bytes: int = HEAP_BYTES,
                 alignment: int = DEFAULT_ALIGNMENT, limit: int | None = None):
        if not positive_power_of_two(heap_bytes) or heap_bytes < MIN_BLOCK:
            raise TraceError("heap size must be a power of two at least 64 bytes")
        if not positive_power_of_two(alignment):
            raise TraceError("heap alignment must be a power of two")
        if limit is None:
            limit = heap_bytes
        if type(limit) is not int or limit < 0:
            raise TraceError("negative or noninteger quota")
        self.heap_bytes = heap_bytes
        self.alignment = alignment
        self.limit = min(limit, heap_bytes)
        self.height = (heap_bytes // MIN_BLOCK).bit_length() - 1
        self.free: list[set[int]] = [set() for _ in range(self.height + 1)]
        self.free[self.height].add(0)
        self.live: dict[str, Allocation] = {}
        self.live_blocks = self.live_requested = 0
        self.peak_blocks = self.peak_requested = self.peak_objects = 0
        self.allocations = self.executed_events = self.restoring_groups = 0

    def allocate(self, name: str, size: int, alignment: int) -> int:
        """Apply alignment/quota/fragmentation admission, then split leftmost."""
        if not isinstance(name, str) or not name or name in self.live:
            raise TraceError(f"empty, nonstring, or already-live allocation ID: {name!r}")
        block = block_bytes(size, alignment)
        if alignment > self.alignment or block > self.heap_bytes:
            raise TraceError(f"unsupported layout for {name}: {size}/{alignment}")
        if block > self.limit - self.live_blocks:
            raise TraceError(f"live-block quota exhausted at {name}")
        wanted = (block // MIN_BLOCK).bit_length() - 1
        candidates = [(min(offsets), order) for order, offsets in
                      enumerate(self.free[wanted:], wanted) if offsets]
        if not candidates:
            raise TraceError(f"fragmentation prevents order {wanted} allocation {name}")
        offset, order = min(candidates)
        self.free[order].remove(offset)
        while order > wanted:
            order -= 1
            self.free[order].add(offset + (MIN_BLOCK << order))
        self.live[name] = Allocation(offset, size, alignment, block)
        self.live_blocks += block
        self.live_requested += size
        self.peak_blocks = max(self.peak_blocks, self.live_blocks)
        self.peak_requested = max(self.peak_requested, self.live_requested)
        self.peak_objects = max(self.peak_objects, len(self.live))
        self.allocations += 1
        return offset

    def release(self, name: str) -> None:
        """Free the original named block and coalesce every free buddy."""
        try:
            allocation = self.live.pop(name)
        except (KeyError, TypeError) as error:
            raise TraceError(f"unknown or already-freed allocation: {name!r}") from error
        offset = allocation.offset
        order = (allocation.block // MIN_BLOCK).bit_length() - 1
        while order < self.height:
            buddy = offset ^ (MIN_BLOCK << order)
            if buddy not in self.free[order]:
                break
            self.free[order].remove(buddy)
            offset = min(offset, buddy)
            order += 1
        self.free[order].add(offset)
        self.live_blocks -= allocation.block
        self.live_requested -= allocation.size

    def state(self) -> tuple:
        """Return exact semantic state, excluding cumulative diagnostics."""
        return (tuple(tuple(sorted(offsets)) for offsets in self.free),
                tuple(sorted(self.live.items())), self.live_blocks,
                self.live_requested)

    def replay(self, events: Iterable[dict[str, Any]], *, depth: int = 0) -> None:
        """Apply events; prove restoring loops by equality after one body.

        A repeat with positive maximum is always checked, even if its minimum
        is zero. If its body restores the entire semantic state, induction
        covers every finite count within the declared range. Declaring that
        range/source grammar to cover the real program is a separate obligation.
        """
        if depth > MAX_EVENT_DEPTH:
            raise TraceError("trace nesting exceeds diagnostic limit")
        for event in events:
            if not isinstance(event, dict):
                raise TraceError("event must be an object")
            op = event.get("op")
            self.executed_events += 1
            if op == "alloc":
                try:
                    self.allocate(event["id"], event["size"], event["align"])
                except KeyError as error:
                    raise TraceError("allocation is missing a required field") from error
            elif op == "free":
                self.release(event.get("id"))
            elif op == "repeat_restoring":
                minimum, maximum, body = event.get("min"), event.get("max"), event.get("body")
                if (type(minimum) is not int or type(maximum) is not int
                        or not 0 <= minimum <= maximum or not isinstance(body, list)):
                    raise TraceError("repeat requires integer 0 <= min <= max and an event body")
                if maximum:
                    before = self.state()
                    count = self.allocations
                    self.replay(body, depth=depth + 1)
                    if self.state() != before:
                        raise TraceError(f"repeat does not restore complete state: {event.get('id')}")
                    self.allocations += (maximum - 1) * (self.allocations - count)
                self.restoring_groups += 1
            else:
                raise TraceError(f"unknown trace operation: {op!r}")

    def report(self, *, require_empty: bool = True) -> dict[str, Any]:
        """Return model results; leak checks do not imply source completeness."""
        if require_empty and self.live:
            raise TraceError(f"trace retains allocations: {sorted(self.live)}")
        return {"heap_bytes": self.heap_bytes, "alignment": self.alignment,
                "limit": self.limit, "peak_block_bytes": self.peak_blocks,
                "peak_requested_bytes": self.peak_requested,
                "peak_live_objects": self.peak_objects,
                "live_exit_block_bytes": self.live_blocks,
                "live_exit_requested_bytes": self.live_requested,
                "allocations_upper_bound": self.allocations,
                "events_executed_by_model": self.executed_events,
                "restoring_groups_checked": self.restoring_groups,
                "trace_replay_passed": True, "complete_workspace_certificate": False,
                "profile_qualified": False}


def main() -> int:
    """Read one trace object and print a conditional allocator result."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path, help="JSON object with events and optional heap settings")
    args = parser.parse_args()
    try:
        data = json.loads(args.trace.read_text())
        if not isinstance(data, dict) or not isinstance(data.get("events"), list):
            raise TraceError("trace must contain an events array")
        buddy = Buddy(data.get("heap_bytes", HEAP_BYTES),
                      data.get("alignment", DEFAULT_ALIGNMENT), data.get("limit"))
        buddy.replay(data["events"])
        print(json.dumps(buddy.report(), indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, RecursionError) as error:
        print(json.dumps({"trace_replay_passed": False, "failure": str(error),
                          "complete_workspace_certificate": False, "profile_qualified": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
