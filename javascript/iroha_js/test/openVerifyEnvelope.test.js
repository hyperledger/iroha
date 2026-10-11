import assert from "node:assert/strict";
import test from "node:test";

import * as publicApi from "../src/index.js";
import * as noritoApi from "../src/norito.js";
import {
  noritoDecodeOpenVerifyEnvelope,
  noritoEncodeOpenVerifyEnvelope,
} from "../src/norito.js";

function envelope(backend) {
  return {
    backend,
    circuit_id: "generic-open-verify-v1",
    vk_hash: Buffer.alloc(32, 0x11),
    public_inputs: Buffer.from([0x22, 0x23]),
    proof_bytes: Buffer.from([0x33, 0x34, 0x35]),
    aux: Buffer.from([0x44]),
  };
}

test("OpenVerify Norito codec exposes only the exact two Rust backend tags", () => {
  for (const backend of ["native-pipa-r-pasta", "stark"]) {
    const encoded = noritoEncodeOpenVerifyEnvelope(envelope(backend));
    const decoded = noritoDecodeOpenVerifyEnvelope(encoded);
    assert.equal(decoded.backend, backend);
    assert.equal(decoded.circuit_id, "generic-open-verify-v1");
    assert.deepEqual(decoded.vk_hash, Array.from(Buffer.alloc(32, 0x11)));
    assert.deepEqual(decoded.public_inputs, [0x22, 0x23]);
    assert.deepEqual(decoded.proof_bytes, [0x33, 0x34, 0x35]);
    assert.deepEqual(decoded.aux, [0x44]);
  }
});

test("OpenVerify backend tags reject aliases and adversarial spellings", () => {
  const hostileLabels = [
    "",
    " ",
    "Stark",
    "STARK",
    " stark",
    "stark ",
    "stark/fri",
    "halo2/ipa",
    "pipa-r/pasta",
    "NativePipaRPasta",
    "native_pipa_r_pasta",
    "native-pipa-r-pasta ",
    "halo2-ipa-pasta",
    "Halo2IpaPasta",
    "halo2_ipa_pasta",
    "halo2‑ipa‑pasta",
    "ѕtark",
    "stark\u0000",
    "groth16",
    "groth16-bls12-377",
    "penumbra",
    "aztec-private-kernel",
    "zkat",
    "silent-threshold-anoncred",
    "sis-hints-anoncred-pq-v0",
    "sis-with-hints",
  ];
  for (const backend of hostileLabels) {
    assert.throws(
      () => noritoEncodeOpenVerifyEnvelope(envelope(backend)),
      /non-empty|unknown or non-canonical backend label/,
      backend,
    );
  }
  for (const backend of [null, undefined, 1, {}, [], new String("stark")]) {
    assert.throws(
      () => noritoEncodeOpenVerifyEnvelope(envelope(backend)),
      /must be a non-empty string/,
    );
  }
});

test("retired privacy-named OpenVerify codec aliases are absent", () => {
  for (const name of [
    "noritoEncodePrivacyProofEnvelope",
    "noritoDecodePrivacyProofEnvelope",
  ]) {
    assert.equal(name in noritoApi, false, name);
    assert.equal(name in publicApi, false, name);
  }
});

test("OpenVerify envelope fields reject lossy normalization and shadow data", () => {
  for (const circuit_id of [
    "",
    " ",
    " generic-open-verify-v1",
    "generic-open-verify-v1 ",
  ]) {
    assert.throws(
      () => noritoEncodeOpenVerifyEnvelope({
        ...envelope("stark"),
        circuit_id,
      }),
      /circuit_id must be a non-empty string|surrounding whitespace/,
    );
  }
  assert.throws(
    () => noritoEncodeOpenVerifyEnvelope({
      ...envelope("stark"),
      backendTag: "stark",
    }),
    /contains unknown field backendTag/,
  );
  assert.throws(
    () => noritoEncodeOpenVerifyEnvelope({
      ...envelope("stark"),
      proof: Buffer.from([0x33]),
    }),
    /contains unknown field proof/,
  );
});
