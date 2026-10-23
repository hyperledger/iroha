import assert from "node:assert/strict";
import test from "node:test";
import { runInNewContext } from "node:vm";
import { _renderCanonicalAccountAddress, AccountAddressError } from "../src/address.js";
import { createNativeRuntime } from "../src/nativeRuntime.js";

test("account rendering returns the Rust owner result with exact bytes and prefix", () => {
  const canonical = Uint8Array.of(2, 0, 1, 32);
  const runtime = createNativeRuntime({
    accountAddressRender(bytes, prefix) {
      assert.deepEqual(bytes, canonical);
      assert.equal(prefix, 369);
      return { canonicalHex: "0x02000120", i105: "rust-owner-result" };
    },
  });
  assert.equal(_renderCanonicalAccountAddress(canonical, 369, runtime), "rust-owner-result");
});

test("digit-containing native I105 diagnostics preserve typed account errors", () => {
  for (const code of ["ERR_INVALID_I105_CHAR", "ERR_INVALID_I105_BASE", "ERR_INVALID_I105_DIGIT"]) {
    const cause = new Error(`${code}: malformed address fixture`);
    assert.throws(() => _renderCanonicalAccountAddress(Uint8Array.of(2), 369, createNativeRuntime({
      accountAddressRender() { throw cause; },
    })), (error) => error instanceof AccountAddressError && error.code === code && error.cause === cause);
  }
});

test("account rendering propagates native rejection and rejects changed identity", () => {
  const rejection = new Error("Rust key admission rejected");
  assert.throws(() => _renderCanonicalAccountAddress(Uint8Array.of(2), 369, createNativeRuntime({
    accountAddressRender() { throw rejection; },
  })), (error) => error === rejection);
  assert.throws(() => _renderCanonicalAccountAddress(Uint8Array.of(2), 369, createNativeRuntime({
    accountAddressRender() { return { canonicalHex: "0x03", i105: "different-account" }; },
  })), /exact canonical identity/);
});

test("numeric I105 sentinel boundary belongs to the canonical owner", async () => {
  const { _parseCanonicalAccountAddress } = await import("../src/address.js");
  for (const literal of ["n422payload", "n423payload"]) {
    const bytes = Uint8Array.of(2, 0, 1, 32);
    const runtime = createNativeRuntime({
      accountAddressParseEncoded(input, expected) {
        assert.equal(input, literal);
        assert.equal(expected, 42);
        return { canonicalBytes: bytes, networkPrefix: 42 };
      },
      accountAddressRender(input, prefix) {
        assert.deepEqual(input, bytes);
        assert.equal(prefix, 42);
        return { canonicalHex: "0x02000120", i105: literal };
      },
    });
    const [prefix, result] = _parseCanonicalAccountAddress(literal, 42, runtime);
    assert.equal(prefix, 42);
    assert.deepEqual(result, bytes);
    result.fill(0);
    assert.deepEqual(bytes, Uint8Array.of(2, 0, 1, 32));
  }
});

test("canonical parse rejects inconsistent owner results and noncanonical rerenders", async () => {
  const { _parseCanonicalAccountAddress } = await import("../src/address.js");
  for (const result of [
    { canonicalBytes: [], networkPrefix: 42 },
    { canonicalBytes: new Uint8Array(), networkPrefix: 42 },
    { canonicalBytes: Uint8Array.of(2), networkPrefix: 422 },
    { canonicalBytes: Uint8Array.of(2), networkPrefix: 42.5 },
    { canonicalBytes: Uint8Array.of(2), networkPrefix: 65536 },
    { canonicalBytes: Uint8Array.of(2), networkPrefix: 42 },
  ]) {
    assert.throws(() => _parseCanonicalAccountAddress("n422payload", 42, createNativeRuntime({
      accountAddressParseEncoded() { return result; },
      accountAddressRender() { return { canonicalHex: "0x02", i105: "changed" }; },
    })), { code: "ERR_UNSUPPORTED_ADDRESS_FORMAT" });
  }
});

test("canonical owner diagnostics preserve prefix and character details", async () => {
  const { _parseCanonicalAccountAddress } = await import("../src/address.js");
  for (const [message, details] of [
    ["ERR_UNEXPECTED_NETWORK_PREFIX: unexpected i105 chain discriminant: expected 42, found 369", { expected: 42, found: 369 }],
    ["ERR_INVALID_I105_CHAR: invalid character `!` in i105 address", { char: "!" }],
  ]) {
    const cause = new Error(message);
    assert.throws(() => _parseCanonicalAccountAddress("input", 42, createNativeRuntime({
      accountAddressParseEncoded() { throw cause; },
    })), (error) => {
      assert.equal(error.cause, cause);
      assert.deepEqual(error.details, details);
      return true;
    });
  }
});

test("canonical owner byte admission accepts real cross-realm Uint8Array and copies its exact window", async () => {
  const { _parseCanonicalAccountAddress } = await import("../src/address.js");
  const foreign = runInNewContext("new Uint8Array([99, 2, 0, 1, 32, 88]).subarray(1, 5)");
  assert.equal(foreign instanceof Uint8Array, false);
  assert.equal(ArrayBuffer.isView(foreign), true);
  const runtime = createNativeRuntime({
    accountAddressParseEncoded() { return { canonicalBytes: foreign, networkPrefix: 369 }; },
    accountAddressRender(bytes, prefix) {
      assert.deepEqual(Array.from(bytes), [2, 0, 1, 32]); assert.equal(prefix, 369);
      return { canonicalHex: "0x02000120", i105: "native-cross-realm" };
    },
  });
  const [prefix, result] = _parseCanonicalAccountAddress("native-cross-realm", 369, runtime);
  assert.equal(prefix, 369); assert.deepEqual(result, Uint8Array.of(2, 0, 1, 32));
  result.fill(0); assert.deepEqual(Array.from(foreign), [2, 0, 1, 32]);
});

test("canonical owner byte admission rejects other views and forged Uint8Array brands", async () => {
  const { _parseCanonicalAccountAddress } = await import("../src/address.js");
  const dataView = new DataView(new ArrayBuffer(4));
  Object.defineProperty(dataView, Symbol.toStringTag, { value: "Uint8Array" });
  const foreignWrongType = runInNewContext("new Uint16Array([2, 0, 1, 32])");
  Object.defineProperty(foreignWrongType, Symbol.toStringTag, { value: "Uint8Array" });
  for (const canonicalBytes of [dataView, foreignWrongType, new Uint8ClampedArray([2, 0, 1, 32]),
    { 0: 2, length: 1, [Symbol.toStringTag]: "Uint8Array", constructor: Uint8Array }, new Proxy(Uint8Array.of(2), {})]) {
    assert.throws(() => _parseCanonicalAccountAddress("invalid-native-bytes", 369, createNativeRuntime({
      accountAddressParseEncoded() { return { canonicalBytes, networkPrefix: 369 }; },
      accountAddressRender() { assert.fail("wrong byte brands must fail before rendering"); },
    })), { code: "ERR_UNSUPPORTED_ADDRESS_FORMAT" });
  }
});


test("known native implementation absence remains separate from unknown identity and invalid key", () => {
  // Injected owner here tests only the existing transport adapter, not actual Rust admission.
  for (const code of ["ERR_DECODE_RESOURCE_LIMIT", "ERR_UNSUPPORTED_IMPLEMENTATION", "ERR_UNKNOWN_CURVE", "ERR_INVALID_PUBLIC_KEY"]) {
    const cause = new Error(`${code}: original address operation`);
    assert.throws(() => _renderCanonicalAccountAddress(Uint8Array.of(2), 369, createNativeRuntime({
      accountAddressRender() { throw cause; },
    })), (error) => error instanceof AccountAddressError && error.code === code && error.cause === cause);
  }
});
