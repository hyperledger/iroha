# Copyright 2026 Hyperledger Iroha Contributors
# SPDX-License-Identifier: Apache-2.0

"""Capture averaging: golden recovery, wrong-frame refusal and bounded state."""

import contextlib
import io
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from petal_test_support import captures_fixture, luma_of

from iroha_petal import (
    DecodeOptions,
    LaneResult,
    Luma,
    RenderOptions,
    ScanSession,
    StreamAssembler,
    StreamEncoder,
    decode_frame,
    render_frame,
)
from iroha_petal.cli import main
from iroha_petal.decode import _merge_tiles, _tile_evidence
from iroha_petal.pngio import write_image
from iroha_petal.session import MERGE_CAPTURES, MERGE_WINDOW


class MergeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = captures_fixture()
        cls.options = DecodeOptions()

    def test_averaging_recovers_recorded_lanes_that_no_capture_reads(self):
        for entry in self.fixture["merges"]:
            with self.subTest(name=entry["name"]):
                evidence = []
                for capture in entry["captures"]:
                    image = luma_of({**entry, **capture})
                    frame = decode_frame(image)
                    self.assertEqual(frame.lanes, capture["reference_decoded"])
                    for letter in entry["must_merge"]:
                        self.assertIsNone(getattr(frame, letter.lower()))
                    evidence.append(_tile_evidence(image, frame, self.options))
                p, k = _merge_tiles(evidence, self.options)
                self.assertEqual(("P" if p else "") + ("K" if k else ""), entry["reference_merged"])
                for letter, result in (("p", p), ("k", k)):
                    if result is not None:
                        self.assertEqual(result.data.hex(), entry[f"{letter}_data"])

    def test_sessions_add_only_newly_recovered_lanes_once(self):
        for entry in self.fixture["merges"]:
            with self.subTest(name=entry["name"]):
                session = ScanSession()
                recovered = ""
                for i, capture in enumerate(entry["captures"]):
                    outcome = session.push(luma_of({**entry, **capture}), 33 * i)
                    self.assertIsNone(outcome.error)
                    recovered += outcome.merged
                for letter in entry["must_merge"]:
                    self.assertEqual(recovered.count(letter), 1)
                    self.assertEqual(getattr(session.stats(), f"lane_{letter.lower()}"), 0)
                self.assertEqual(session.stats().merged_p, int("P" in recovered))
                self.assertEqual(session.stats().merged_k, int("K" in recovered))

    def test_mixed_frame_tile_lanes_never_enter_the_assembler(self):
        for entry in self.fixture["mixed_merges"]:
            with self.subTest(name=entry["name"]):
                session = ScanSession()
                baseline = StreamAssembler()
                evidence = []
                for i, capture in enumerate(entry["captures"]):
                    image = luma_of({**entry, **capture})
                    frame = decode_frame(image)
                    self.assertEqual(frame.lanes, capture["reference_decoded"])
                    frame.feed(baseline)
                    evidence.append(_tile_evidence(image, frame, self.options))
                    self.assertEqual(session.push(image, 33 * i).merged, "")
                p, k = _merge_tiles(evidence, self.options)
                self.assertEqual(("P" if p else "") + ("K" if k else ""), entry["reference_merged"])
                self.assertEqual(int.from_bytes(p.data[1:3], "big"), entry["tiles_frame"])
                self.assertEqual(session.progress(), baseline.progress())
                self.assertEqual(session.stats().merged_p + session.stats().merged_k, 0)
                self.assertGreater(session.stats().merges, 0)

    def test_one_capture_matches_normal_decode_and_invalid_evidence_is_refused(self):
        for name in ("clean-512", "shadow-band-540p", "hidden-corner-540p", "selfie-mirrored-540p"):
            entry = next(c for c in self.fixture["captures"] if c["name"] == name)
            image = luma_of(entry)
            frame = decode_frame(image)
            evidence = _tile_evidence(image, frame, self.options)
            self.assertEqual(_merge_tiles([evidence], self.options), (frame.p, frame.k), name)
            self.assertIsNone(_tile_evidence(Luma(20, 20), frame, self.options))
            self.assertIsNone(
                _tile_evidence(image, replace(frame, inferred_corner=7), self.options)
            )
        self.assertEqual(_merge_tiles([], self.options), (None, None))

    def test_command_line_reports_recovered_lanes(self):
        entry = self.fixture["merges"][0]
        out, err = io.StringIO(), io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            frames = root / "frames"
            frames.mkdir()
            for i, capture in enumerate(entry["captures"]):
                write_image(frames / f"{i:02}.pgm", luma_of({**entry, **capture}))
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                status = main(
                    ["decode", "--input-dir", str(frames), "--output", str(root / "out.bin")]
                )
        self.assertEqual(status, 1)  # these captures contain one shown frame, not a whole stream
        self.assertIn("(merged K)", err.getvalue())
        self.assertIn("1 merged K", err.getvalue())

    def test_conflicting_headers_bounds_and_reset_preserve_capture_isolation(self):
        encoder = StreamEncoder(bytes(i & 255 for i in range(700)), 2)
        image = render_frame(encoder.cells(11), RenderOptions(size=512, supersample=2)).to_luma()
        decoded = decode_frame(image)

        def rings(number):
            return replace(decoded, p=None, k=None,
                           d=LaneResult(encoder.lane_data(number)[2], 0, 0))

        session = ScanSession()
        self.assertEqual(session._merge(image, replace(rings(10), p=decoded.p)), "")
        self.assertEqual(len(session._held), 0)
        self.assertEqual(session._merge(image, replace(decoded, p=None, k=None, d=None)), "")
        self.assertEqual(len(session._held), 0)
        for _ in range(MERGE_CAPTURES + 2):
            self.assertEqual(session._merge(image, rings(10)), "")
        self.assertEqual(len(session._held[0].evidence), MERGE_CAPTURES)
        self.assertEqual(session.progress().atoms_received, 0)
        for number in range(12, 12 + MERGE_WINDOW):
            session._merge(image, rings(number))
        self.assertEqual(len(session._held), MERGE_WINDOW)
        self.assertEqual(session._held[0].shown.frame, 12)
        self.assertTrue(all(len(h.evidence) <= MERGE_CAPTURES for h in session._held))
        self.assertEqual(len(ScanSession()._held), 0)
        session.reset()
        self.assertEqual(len(session._held), 0)
        self.assertEqual(session._merge(image, rings(10)), "")
        self.assertEqual(len(session._held[0].evidence), 1)
        beacon = render_frame(encoder.cells(0), RenderOptions(size=512, supersample=2)).to_luma()
        session.push(beacon, 0)
        self.assertIsNotNone(session.progress().meta)
        session.push(Luma(320, 240), 60_000)
        self.assertEqual(len(session._held), 0, "timeout forgets the previous stream's evidence")


    def test_same_tag_stream_switch_clears_old_done_flags_and_evidence(self):
        old_encoder = StreamEncoder((49).to_bytes(4, "big") + bytes(96), 2)
        new_encoder = StreamEncoder((128).to_bytes(4, "big") + bytes(96), 2)
        self.assertEqual(old_encoder.meta.tag, new_encoder.meta.tag)
        self.assertNotEqual(old_encoder.meta, new_encoder.meta)
        image = render_frame(new_encoder.cells(0), RenderOptions(size=512, supersample=1)).to_luma()
        decoded = decode_frame(image)

        def frame_of(encoder, number, only_d=False):
            p, k, d = encoder.lane_data(number)
            return replace(decoded, p=None if only_d else LaneResult(p, 0, 0),
                           k=None if only_d else LaneResult(k, 0, 0), d=LaneResult(d, 0, 0))

        old_frame = frame_of(old_encoder, 0)
        new_only_d = frame_of(new_encoder, 0, True)
        session = ScanSession()
        session._absorb(old_frame)
        session._merge(image, old_frame)
        session._absorb(frame_of(old_encoder, 1))
        self.assertTrue(session.progress().complete)
        self.assertTrue(session._held[0].p_done and session._held[0].k_done)
        session._absorb(new_only_d)
        session._merge(image, new_only_d)
        self.assertEqual(session.progress().meta, old_encoder.meta)
        session._absorb(new_only_d)
        session._merge(image, new_only_d)
        self.assertEqual(session.progress().meta, new_encoder.meta)
        self.assertFalse(session._held[0].p_done or session._held[0].k_done)
        self.assertEqual(len(session._held[0].evidence), 1)
        self.assertEqual(session._merge(image, new_only_d), "PK")
        self.assertEqual(session._merge(image, new_only_d), "")

        partial = ScanSession()
        old_only_d = frame_of(old_encoder, 0, True)
        partial._absorb(old_only_d)
        partial._merge(image, old_only_d)
        old_evidence = partial._held[0].evidence[0]
        partial._absorb(new_only_d)
        self.assertIs(partial._held[0].evidence[0], old_evidence)
        partial._absorb(new_only_d)
        self.assertEqual(len(partial._held), 0)
        partial._merge(image, new_only_d)
        self.assertIsNot(partial._held[0].evidence[0], old_evidence)
        self.assertEqual(len(partial._held[0].evidence), 1)
        self.assertEqual(partial.stats().merges, 0)

        # Captures awaiting the first beacon remain useful when it arrives.
        before_beacon = ScanSession()
        before_beacon._merge(image, new_only_d)
        evidence = before_beacon._held[0].evidence[0]
        before_beacon._absorb(new_only_d)
        self.assertIs(before_beacon._held[0].evidence[0], evidence)
