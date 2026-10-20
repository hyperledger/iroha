# Copyright 2026 Hyperledger Iroha Contributors
# SPDX-License-Identifier: Apache-2.0

"""The receive-side object an app holds while its camera is open.

After a frame decodes, the next frames are first read by tracking the code from
its last pose (:func:`~iroha_petal.decode.track_frame`), which skips the finder
search; a full :func:`~iroha_petal.decode.decode_frame` runs when tracking fails
or the last pose is older than :data:`TRACK_WINDOW_MS`. Repeated captures whose
independently decoded lane headers agree are averaged to recover missing tile
lanes, keeping at most four captures of six shown frames.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field, replace
from typing import Deque, Optional, Tuple

from .decode import (
    DecodedFrame,
    DecodeError,
    DecodeErrorKind,
    DecodeOptions,
    _TileEvidence,
    _merge_tiles,
    _tile_evidence,
    decode_frame,
    track_frame,
)
from .image import Luma
from .lanes import Lane
from .stream import (
    AssemblerLimits,
    Completed,
    LaneHeader,
    Progress,
    StreamAssembler,
    parse_atom_lane,
)

__all__ = ["TRACK_WINDOW_MS", "ScanLimits", "ScanStats", "ScanOutcome", "ScanSession"]

#: How long a decoded pose stays usable for tracking the next frames.
TRACK_WINDOW_MS = 500
#: Shown frames whose captures are held for merging.
MERGE_WINDOW = 6
#: Captures per shown frame; further captures replace the oldest.
MERGE_CAPTURES = 4


@dataclass(frozen=True)
class ScanLimits:
    """Limits of a scan session."""

    #: Forget a half-received stream after this long without progress.
    idle_timeout_ms: int = 30_000
    #: Forget a stream that has not finished this long after it started.
    absolute_timeout_ms: int = 180_000
    #: Assembler memory and size limits.
    assembler: AssemblerLimits = field(default_factory=AssemblerLimits)
    #: Image decoder options.
    decode: DecodeOptions = field(default_factory=DecodeOptions)


@dataclass(frozen=True)
class ScanStats:
    """Counters for diagnostics and UI hints."""

    #: Camera frames offered.
    frames: int = 0
    #: Frames in which a code was located, whether or not a lane could be read.
    located: int = 0
    #: Frames in which at least one lane decoded.
    readable: int = 0
    #: Lane ``P`` successes.
    lane_p: int = 0
    #: Lane ``K`` successes.
    lane_k: int = 0
    #: Lane ``D`` successes.
    lane_d: int = 0
    #: Frames read by tracking the previous pose instead of a full search.
    tracked: int = 0
    #: Frames read with one corner finder hidden and inferred.
    inferred: int = 0
    #: Merges of two or more captures of one shown frame.
    merges: int = 0
    #: Lane ``P`` reads recovered by merging captures.
    merged_p: int = 0
    #: Lane ``K`` reads recovered by merging captures.
    merged_k: int = 0


@dataclass(frozen=True)
class ScanOutcome:
    """The result of offering one camera frame."""

    #: Why the frame produced nothing, when it did not. ``NO_ORIENTATION``
    #: means a code was located but no lane could be read (too far, too blurry).
    error: Optional[DecodeErrorKind]
    #: Lanes that decoded, as letters from ``"PKD"``.
    lanes: str
    #: Receive progress after this frame.
    progress: Progress
    #: The finished payload, delivered exactly once.
    completed: Optional[Completed]
    #: Tile lanes newly recovered by merging, as letters from ``"PK"``.
    merged: str = ""


@dataclass
class _Held:
    """The bounded captures of one independently identified shown frame."""

    shown: LaneHeader
    evidence: Deque[_TileEvidence] = field(default_factory=deque)
    p_done: bool = False
    k_done: bool = False


def _shown_frame(frame: DecodedFrame) -> Optional[LaneHeader]:
    """Require every independently decoded lane to name the same shown frame."""
    shown = None
    for lane in (frame.d, frame.p, frame.k):
        if lane is None:
            continue
        if len(lane.data) < 3:
            return None
        header = LaneHeader(lane.data[0], int.from_bytes(lane.data[1:3], "big"))
        if shown is not None and shown != header:
            return None
        shown = header
    return shown


class ScanSession:
    """Decodes camera frames and reassembles the stream they carry."""

    def __init__(self, limits: Optional[ScanLimits] = None) -> None:
        self._limits = limits if limits is not None else ScanLimits()
        self._assembler = StreamAssembler(self._limits.assembler)
        self._stats = ScanStats()
        self._started_ms: Optional[int] = None
        self._progress_ms = 0
        self._last_rank = 0
        self._last_pose: Optional[Tuple[DecodedFrame, int]] = None
        self._held: Deque[_Held] = deque()

    @property
    def limits(self) -> ScanLimits:
        """The limits of this session."""
        return self._limits

    def stats(self) -> ScanStats:
        """Diagnostic counters."""
        return self._stats

    def progress(self) -> Progress:
        """Current progress."""
        return self._assembler.progress()

    def reset(self) -> None:
        """Drop all partial state."""
        self._assembler.reset()
        self._started_ms = None
        self._last_rank = 0
        self._last_pose = None
        self._held.clear()

    def push(self, image: Luma, now_ms: int) -> ScanOutcome:
        """Offer one camera luma plane captured at monotonic time ``now_ms``.

        While the last decoded pose is at most :data:`TRACK_WINDOW_MS` old the frame
        is first read by tracking that pose; a full decode runs when tracking fails.
        """
        start = self._started_ms
        if start is not None and (
            max(now_ms - self._progress_ms, 0) > self._limits.idle_timeout_ms
            or max(now_ms - start, 0) > self._limits.absolute_timeout_ms
        ):
            self.reset()
        self._stats = replace(self._stats, frames=self._stats.frames + 1)
        error: Optional[DecodeErrorKind] = None
        lanes = ""
        merged = ""
        frame: Optional[DecodedFrame] = None
        last_pose = self._last_pose
        if last_pose is not None and max(now_ms - last_pose[1], 0) <= TRACK_WINDOW_MS:
            frame = track_frame(image, last_pose[0], self._limits.decode)
            if frame is not None:
                self._stats = replace(self._stats, tracked=self._stats.tracked + 1)
        if frame is None:
            try:
                frame = decode_frame(image, self._limits.decode)
            except DecodeError as failure:
                error = failure.kind
        if frame is not None:
            if frame.inferred_corner is not None:
                self._stats = replace(self._stats, inferred=self._stats.inferred + 1)
            self._last_pose = (frame, now_ms)
            lanes = self._absorb(frame)
            merged = self._merge(image, frame)
        if error not in (DecodeErrorKind.NO_FINDERS, DecodeErrorKind.UNSUPPORTED_IMAGE):
            self._stats = replace(self._stats, located=self._stats.located + 1)
        progress = self._assembler.progress()
        if progress.rank > self._last_rank or (
            progress.meta is not None and self._started_ms is None
        ):
            self._progress_ms = now_ms
            if self._started_ms is None:
                self._started_ms = now_ms
        self._last_rank = progress.rank
        return ScanOutcome(
            error=error,
            lanes=lanes,
            merged=merged,
            progress=progress,
            completed=self._assembler.take_completed(),
        )

    def push_plane(
        self, width: int, height: int, stride: int, plane: bytes, now_ms: int
    ) -> ScanOutcome:
        """Offer the luma (Y) plane of a camera frame, rows ``stride`` bytes apart.

        This is the camera-analyzer entry point: NV12/NV21/I420 frames carry
        their luma first, so pass that plane and its row stride directly.
        """
        return self.push(Luma.from_strided(width, height, stride, plane), now_ms)

    def _merge(self, image: Luma, frame: DecodedFrame) -> str:
        """Average only captures keyed by an independently decoded lane header."""
        shown = _shown_frame(frame)
        if shown is None:
            return ""
        held = next((h for h in self._held if h.shown == shown), None)
        if held is None:
            if len(self._held) == MERGE_WINDOW:
                self._held.popleft()
            held = _Held(shown)
            self._held.append(held)
        held.p_done |= frame.p is not None
        held.k_done |= frame.k is not None
        if held.p_done and held.k_done:
            held.evidence.clear()
            return ""
        evidence = _tile_evidence(image, frame, self._limits.decode)
        if evidence is None:
            return ""
        if len(held.evidence) == MERGE_CAPTURES:
            held.evidence.popleft()
        held.evidence.append(evidence)
        if len(held.evidence) < 2:
            return ""
        self._stats = replace(self._stats, merges=self._stats.merges + 1)
        p, k = _merge_tiles(list(held.evidence), self._limits.decode)
        merged = ""
        for letter, lane, result, done, counter in (
            ("P", Lane.P, p, "p_done", "merged_p"),
            ("K", Lane.K, k, "k_done", "merged_k"),
        ):
            packet = parse_atom_lane(lane, result.data) if result is not None else None
            if getattr(held, done) or packet is None or packet.header != shown:
                continue
            setattr(held, done, True)
            self._assembler.push_atoms(packet)
            self._stats = replace(self._stats, **{counter: getattr(self._stats, counter) + 1})
            merged += letter
        if held.p_done and held.k_done:
            held.evidence.clear()
        return merged

    def _absorb(self, frame: DecodedFrame) -> str:
        lanes = frame.lanes
        stats = self._stats
        self._stats = replace(
            stats,
            lane_p=stats.lane_p + (frame.p is not None),
            lane_k=stats.lane_k + (frame.k is not None),
            lane_d=stats.lane_d + (frame.d is not None),
            readable=stats.readable + (1 if lanes else 0),
        )
        previous_meta = self._assembler.progress().meta
        frame.feed(self._assembler)
        current_meta = self._assembler.progress().meta
        # Tags are only eight bits. Evidence and done flags belong to the full
        # stream identity; captures preceding the first beacon remain useful.
        if previous_meta is not None and current_meta != previous_meta:
            self._held.clear()
        return lanes
