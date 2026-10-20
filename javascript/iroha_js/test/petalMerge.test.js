import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { inflateSync } from "node:zlib";

import {
  PETAL_DEFAULT_DECODE_OPTIONS,
  PetalDecodedFrame,
  PetalLuma,
  PetalScanSession,
  PetalStreamAssembler,
  PetalStreamEncoder,
  decodePetalFrame,
  renderPetalFrame,
} from "../src/petal.js";
import { mergeTiles, tileEvidence } from "../src/petal/decode.js";
import { MERGE_CAPTURES, MERGE_WINDOW } from "../src/petal/session.js";

const fixture = JSON.parse(readFileSync(new URL("../../../fixtures/petal/petal_captures_v1.json", import.meta.url)));
const options = PETAL_DEFAULT_DECODE_OPTIONS;
const hex = (bytes) => Buffer.from(bytes).toString("hex");
const imageOf = (set, capture) => new PetalLuma(set.width, set.height,
  new Uint8Array(inflateSync(Buffer.from(capture.luma_zlib_base64, "base64"))));
const lanes = (frame) => ["p", "k", "d"].filter((key) => frame[key] !== null).join("").toUpperCase();

for (const set of fixture.merges) {
  test(`petal averaging: ${set.name} recovers the recorded tile lanes`, () => {
    const evidence = [];
    for (const capture of set.captures) {
      const image = imageOf(set, capture);
      const frame = decodePetalFrame(image);
      assert.equal(lanes(frame), capture.reference_decoded);
      for (const letter of set.must_merge) assert.equal(frame[letter.toLowerCase()], null);
      evidence.push(tileEvidence(image, frame, options));
    }
    const recovered = mergeTiles(evidence, options);
    const letters = ["p", "k"].filter((key) => recovered[key] !== null).join("").toUpperCase();
    assert.equal(letters, set.reference_merged);
    for (const key of ["p", "k"]) {
      if (recovered[key] !== null) assert.equal(hex(recovered[key].data), set[`${key}_data`]);
    }
  });

  test(`petal session: ${set.name} adds only newly recovered lanes once`, () => {
    const session = new PetalScanSession();
    let recovered = "";
    for (const [i, capture] of set.captures.entries()) {
      const outcome = session.push(imageOf(set, capture), 33 * i);
      recovered += outcome.merged;
      assert.equal(outcome.error, null);
    }
    for (const letter of set.must_merge) assert.equal(recovered.split(letter).length - 1, 1);
    assert.equal(session.stats().mergedP, recovered.includes("P") ? 1 : 0);
    assert.equal(session.stats().mergedK, recovered.includes("K") ? 1 : 0);
    for (const letter of set.must_merge) assert.equal(session.stats()[`lane${letter}`], 0);
  });
}

test("petal averaging: mixed-frame tile lanes never enter the assembler", () => {
  for (const set of fixture.mixed_merges) {
    const session = new PetalScanSession();
    const baseline = new PetalStreamAssembler();
    const evidence = [];
    for (const [i, capture] of set.captures.entries()) {
      const image = imageOf(set, capture);
      const frame = decodePetalFrame(image);
      assert.equal(lanes(frame), capture.reference_decoded);
      frame.feed(baseline);
      evidence.push(tileEvidence(image, frame, options));
      assert.equal(session.push(image, 33 * i).merged, "");
    }
    const recovered = mergeTiles(evidence, options);
    assert.equal(["p", "k"].filter((key) => recovered[key] !== null).join("").toUpperCase(), set.reference_merged);
    assert.equal((recovered.p.data[1] << 8) | recovered.p.data[2], set.tiles_frame);
    assert.deepEqual(session.progress(), baseline.progress());
    assert.equal(session.stats().mergedP + session.stats().mergedK, 0);
    assert.ok(session.stats().merges > 0);
  }
});

test("petal evidence: one capture matches normal decoding and rejects unusable inputs", () => {
  for (const name of ["clean-512", "shadow-band-540p", "hidden-corner-540p", "selfie-mirrored-540p"]) {
    const capture = fixture.captures.find((c) => c.name === name);
    const image = imageOf(capture, capture);
    const frame = decodePetalFrame(image);
    const evidence = tileEvidence(image, frame, options);
    assert.deepEqual(mergeTiles([evidence], options), { p: frame.p, k: frame.k }, name);
    assert.equal(tileEvidence(new PetalLuma(20, 20), frame, options), null);
    const invalid = new PetalDecodedFrame(frame.homography, frame.rotation, frame.mirrored,
      frame.p, frame.k, frame.d, 7);
    assert.equal(tileEvidence(image, invalid, options), null);
  }
  assert.deepEqual(mergeTiles([], options), { p: null, k: null });
});

test("petal session: conflicting headers, bounds and reset preserve capture isolation", () => {
  const encoder = new PetalStreamEncoder(new Uint8Array(700).map((_, i) => i & 255), 2);
  const rendered = renderPetalFrame(encoder.cells(11), { size: 512, supersample: 2 });
  const image = PetalLuma.fromRgba(rendered.width, rendered.height, rendered.data);
  const decoded = decodePetalFrame(image);
  const rings = (frame) => new PetalDecodedFrame(decoded.homography, decoded.rotation,
    decoded.mirrored, null, null, { data: encoder.laneData(frame).d, corrected: 0, erasures: 0 }, null);
  const session = new PetalScanSession();
  const torn = new PetalDecodedFrame(decoded.homography, 0, false, decoded.p, null, rings(10).d, null);
  assert.equal(session._merge(image, torn), "");
  assert.equal(session._held.length, 0);
  const noHeader = new PetalDecodedFrame(decoded.homography, 0, false, null, null, null, null);
  assert.equal(session._merge(image, noHeader), "");
  assert.equal(session._held.length, 0);
  for (let i = 0; i < MERGE_CAPTURES + 2; i += 1) assert.equal(session._merge(image, rings(10)), "");
  assert.equal(session._held[0].evidence.length, MERGE_CAPTURES);
  assert.equal(session.progress().atomsReceived, 0);
  for (let i = 12; i < 12 + MERGE_WINDOW; i += 1) session._merge(image, rings(i));
  assert.equal(session._held.length, MERGE_WINDOW);
  assert.equal(session._held[0].shown.frame, 12);
  assert.ok(session._held.every((h) => h.evidence.length <= MERGE_CAPTURES));
  const other = new PetalScanSession();
  assert.equal(other._held.length, 0);
  session.reset();
  assert.equal(session._held.length, 0);
  assert.equal(session._merge(image, rings(10)), "");
  assert.equal(session._held[0].evidence.length, 1);
  const beacon = renderPetalFrame(encoder.cells(0), { size: 512, supersample: 2 });
  session.push(PetalLuma.fromRgba(beacon.width, beacon.height, beacon.data), 0);
  assert.notEqual(session.progress().meta, null);
  session.push(new PetalLuma(320, 240), 60_000);
  assert.equal(session._held.length, 0, "timeout forgets the previous stream's evidence");
});


test("petal session: a same-tag stream switch clears old done flags and evidence", () => {
  const payload = (value) => {
    const bytes = new Uint8Array(100);
    new DataView(bytes.buffer).setUint32(0, value);
    return bytes;
  };
  const oldEncoder = new PetalStreamEncoder(payload(49), 2);
  const newEncoder = new PetalStreamEncoder(payload(128), 2);
  assert.equal(oldEncoder.meta.tag, newEncoder.meta.tag);
  assert.notDeepEqual(oldEncoder.meta, newEncoder.meta);
  const rendered = renderPetalFrame(newEncoder.cells(0), { size: 512, supersample: 1 });
  const image = PetalLuma.fromRgba(rendered.width, rendered.height, rendered.data);
  const decoded = decodePetalFrame(image);
  const frameOf = (encoder, number, onlyD = false) => {
    const data = encoder.laneData(number);
    const result = (bytes) => ({ data: bytes, corrected: 0, erasures: 0 });
    return new PetalDecodedFrame(decoded.homography, decoded.rotation, decoded.mirrored,
      onlyD ? null : result(data.p), onlyD ? null : result(data.k), result(data.d), null);
  };
  const oldFrame = frameOf(oldEncoder, 0);
  const newOnlyD = frameOf(newEncoder, 0, true);
  const session = new PetalScanSession();
  session._absorb(oldFrame);
  session._merge(image, oldFrame);
  session._absorb(frameOf(oldEncoder, 1));
  assert.equal(session.progress().complete, true);
  assert.equal(session._held[0].pDone && session._held[0].kDone, true);
  session._absorb(newOnlyD);
  session._merge(image, newOnlyD);
  assert.equal(session.progress().meta.crc, oldEncoder.meta.crc, "one conflicting beacon cannot switch streams");
  session._absorb(newOnlyD);
  session._merge(image, newOnlyD);
  assert.equal(session.progress().meta.crc, newEncoder.meta.crc);
  assert.equal(session._held[0].pDone || session._held[0].kDone, false);
  assert.equal(session._held[0].evidence.length, 1);
  assert.equal(session._merge(image, newOnlyD), "PK");
  assert.equal(session._merge(image, newOnlyD), "");

  const partial = new PetalScanSession();
  const oldOnlyD = frameOf(oldEncoder, 0, true);
  partial._absorb(oldOnlyD);
  partial._merge(image, oldOnlyD);
  const oldEvidence = partial._held[0].evidence[0];
  partial._absorb(newOnlyD);
  assert.equal(partial._held[0].evidence[0], oldEvidence, "one conflicting beacon preserves the active stream");
  partial._absorb(newOnlyD);
  assert.equal(partial._held.length, 0, "an accepted stream switch discards partial evidence");
  partial._merge(image, newOnlyD);
  assert.notEqual(partial._held[0].evidence[0], oldEvidence);
  assert.equal(partial._held[0].evidence.length, 1);
  assert.equal(partial.stats().merges, 0);

  // Evidence acquired before the first beacon survives initial stream admission.
  const beforeBeacon = new PetalScanSession();
  beforeBeacon._merge(image, newOnlyD);
  const evidence = beforeBeacon._held[0].evidence[0];
  beforeBeacon._absorb(newOnlyD);
  assert.equal(beforeBeacon._held[0].evidence[0], evidence);
});
