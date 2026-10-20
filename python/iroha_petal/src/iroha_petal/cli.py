# Copyright 2026 Hyperledger Iroha Contributors
# SPDX-License-Identifier: Apache-2.0

"""Command-line interface: ``python3 -m iroha_petal {encode,decode,inspect}``.

* ``encode`` renders numbered frames of a payload stream (PNG, PGM or SVG).
* ``decode`` feeds image files (any order) through a :class:`ScanSession` and
  writes the reassembled payload; it reports how many frames were read by
  tracking the previous pose and how many had a hidden corner blossom.
* ``inspect`` reports what one image decodes to, including a hidden (inferred)
  corner blossom.

No network and no camera access: frames are files.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional, Sequence

from .decode import DecodeError, decode_frame
from .pngio import read_luma, write_image
from .render import RenderOptions, draw_list, render_frame
from .session import ScanSession
from .stream import AtomPacket, Beacon, StreamEncoder, StreamError

__all__ = ["main"]

_IMAGE_SUFFIXES = (".png", ".pgm", ".ppm")


def _encode(args: argparse.Namespace) -> int:
    payload = Path(args.input).read_bytes()
    try:
        encoder = StreamEncoder(payload, args.kind)
    except (StreamError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    systematic = encoder.systematic_frames()
    frames = args.frames if args.frames is not None else max(4, 2 * systematic)
    if not 1 <= frames <= 65_536:
        print("error: --frames must be within 1..=65536", file=sys.stderr)
        return 2
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    options = RenderOptions(size=args.size, supersample=args.supersample)
    width = max(4, len(str(frames - 1)))
    for frame in range(frames):
        cells = encoder.cells(frame)
        name = output / f"frame_{frame:0{width}d}.{args.format}"
        if args.format == "svg":
            name.write_text(draw_list(cells).to_svg(args.size), encoding="utf-8")
        else:
            image = render_frame(cells, options)
            write_image(name, image.to_luma() if args.format == "pgm" else image)
    meta = encoder.meta
    print(
        f"wrote {frames} frames to {output} (payload {meta.length} bytes, kind {meta.kind}, "
        f"crc32c 0x{meta.crc:08x}, {meta.source_atoms} source atoms, "
        f"{systematic} systematic frames)"
    )
    return 0


def _collect(args: argparse.Namespace) -> List[Path]:
    paths: List[Path] = [Path(p) for p in (args.input or [])]
    if args.input_dir:
        directory = Path(args.input_dir)
        paths.extend(sorted(p for p in directory.iterdir() if p.suffix.lower() in _IMAGE_SUFFIXES))
    return paths


def _decode(args: argparse.Namespace) -> int:
    paths = _collect(args)
    if not paths:
        print("error: no input frames (use --input or --input-dir)", file=sys.stderr)
        return 2
    session = ScanSession()
    completed = None
    stats = session.stats()
    for index, path in enumerate(paths):
        image = read_luma(path)
        factor_note = ""
        if args.max_side and max(image.width, image.height) > args.max_side:
            factor = -(-max(image.width, image.height) // args.max_side)
            image = image.downscaled(factor)
            factor_note = f" (downscaled 1/{factor})"
        outcome = session.push(image, index * args.frame_interval_ms)
        status = outcome.error.value if outcome.error is not None else (outcome.lanes or "-")
        before, stats = stats, session.stats()
        if stats.tracked > before.tracked:
            status += " (tracked)"
        if stats.inferred > before.inferred:
            status += " (one corner blossom is hidden)"
        if outcome.merged:
            status += f" (merged {outcome.merged})"
        progress = outcome.progress
        if not args.quiet:
            print(
                f"{path.name}: {status}{factor_note}; rank {progress.rank}/{progress.source_atoms}",
                file=sys.stderr,
            )
        if outcome.completed is not None:
            completed = outcome.completed
            break
    if not args.quiet:
        print(
            f"frames: {stats.frames} read, {stats.located} located, {stats.readable} readable, "
            f"{stats.tracked} tracked, {stats.inferred} with a hidden corner blossom, "
            f"{stats.merges} merges, {stats.merged_p} merged P, {stats.merged_k} merged K",
            file=sys.stderr,
        )
    if completed is None:
        progress = session.progress()
        print(
            f"incomplete: rank {progress.rank}/{progress.source_atoms} after {len(paths)} frames",
            file=sys.stderr,
        )
        return 1
    Path(args.output).write_bytes(completed.payload)
    print(
        f"wrote {len(completed.payload)} bytes to {args.output} "
        f"(kind {completed.meta.kind}, crc32c 0x{completed.meta.crc:08x})"
    )
    return 0


def _inspect(args: argparse.Namespace) -> int:
    image = read_luma(args.file)
    print(f"image: {image.width}x{image.height}")
    try:
        frame = decode_frame(image, max_side=args.max_side)
    except DecodeError as error:
        print(f"no decode: {error.kind.name.lower()} ({error})")
        return 1
    m = frame.homography.m
    print(f"orientation: rotation {frame.rotation} quarter turns, mirrored {frame.mirrored}")
    if frame.inferred_corner is not None:
        # canonical index: 0 top-left, 1 top-right, 2 bottom-right, 3 bottom-left
        corner = ("top-left", "top-right", "bottom-right", "bottom-left")[frame.inferred_corner]
        print(f"inferred corner: {frame.inferred_corner} ({corner} blossom hidden)")
    print("homography (canvas -> pixels):")
    for row in range(3):
        print("  " + "  ".join(f"{m[row * 3 + col]: .6g}" for col in range(3)))
    for name, (x, y) in (
        ("canvas centre", (512.0, 512.0)),
        ("top-left finder", (72.0, 72.0)),
        ("bottom-right finder", (952.0, 952.0)),
    ):
        px, py = frame.homography.apply(x, y)
        print(f"  {name}: ({px:.1f}, {py:.1f})")
    for letter, result in (("P", frame.p), ("K", frame.k), ("D", frame.d)):
        if result is None:
            print(f"lane {letter}: not decoded")
        else:
            print(f"lane {letter}: ok ({result.erasures} erasures) {result.data.hex()}")
    lane = frame.d_lane()
    if isinstance(lane, Beacon):
        meta = lane.meta
        print(
            f"beacon: frame {lane.header.frame}, kind {meta.kind}, length {meta.length}, "
            f"crc32c 0x{meta.crc:08x}"
        )
    for packet in frame.atom_packets():
        assert isinstance(packet, AtomPacket)
        last = packet.first_id + len(packet.atoms) - 1
        print(
            f"atoms: tag 0x{packet.header.tag:02x} frame {packet.header.frame} "
            f"ids {packet.first_id}..{last}"
        )
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m iroha_petal",
        description="Petal Stream optical transport: render frames, decode captures.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    encode = commands.add_parser("encode", help="render the frames of a payload stream")
    encode.add_argument("--input", required=True, help="payload file")
    encode.add_argument("--output", required=True, help="output directory")
    encode.add_argument("--kind", type=int, default=0, help="payload kind byte (default 0)")
    encode.add_argument(
        "--frames",
        type=int,
        help="number of frames (default: twice the systematic frames, at least 4)",
    )
    encode.add_argument("--size", type=int, default=768, help="frame side in pixels (default 768)")
    encode.add_argument(
        "--supersample", type=int, default=2, help="anti-aliasing samples per side, 1-4 (default 2)"
    )
    encode.add_argument("--format", choices=("png", "pgm", "svg"), default="png")
    encode.set_defaults(handler=_encode)

    decode = commands.add_parser("decode", help="reassemble a payload from captured frames")
    decode.add_argument("--input", action="append", help="frame image (repeatable)")
    decode.add_argument("--input-dir", help="directory of PNG/PGM/PPM frames, read in name order")
    decode.add_argument("--output", required=True, help="where to write the payload")
    decode.add_argument(
        "--max-side",
        type=int,
        default=1280,
        help="downscale larger frames to fit this side before decoding (0 disables; default 1280)",
    )
    decode.add_argument(
        "--frame-interval-ms",
        type=int,
        default=100,
        help="timestamp spacing between frames for the session timeouts (default 100)",
    )
    decode.add_argument("--quiet", action="store_true", help="do not report every frame")
    decode.set_defaults(handler=_decode)

    inspect = commands.add_parser("inspect", help="report what one image decodes to")
    inspect.add_argument("file", help="PNG, PGM or PPM image")
    inspect.add_argument(
        "--max-side", type=int, default=None, help="downscale larger images to fit this side"
    )
    inspect.set_defaults(handler=_inspect)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the command line; returns the process exit status."""
    args = _parser().parse_args(argv)
    return int(args.handler(args))


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
