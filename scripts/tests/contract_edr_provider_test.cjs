"use strict";

// Run through sccp_evm_contract_smoke.sh after the audited native runtime install,
// or directly: NODE_PATH=<installed evm-runtime>/node_modules node --test <this file>.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const { createNativeEdrProvider } = require("../contract_tooling/evm-runtime/edr-provider.js");
const { rejectedWith } = require("../contract_tooling/evm-runtime/evm-errors.js");
const { AbiCoder } = require("ethers");
const { BrowserProvider } = require("ethers");

const HARDFORKS = ["prague", "osaka"];
// EIP-2537 precompiles used by the SCCP destination (`specs/sccp.md` §5.2.4).
const G1ADD = "0x000000000000000000000000000000000000000b";
const PAIRING_CHECK = "0x000000000000000000000000000000000000000f";
const MAP_FP2_TO_G2 = "0x0000000000000000000000000000000000000011";
const FIELD_MODULUS = BigInt("0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab");
const G1_X = "17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
const G1_Y = "08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";
const fieldWord = (limb) => `${"00".repeat(16)}${limb}`;
const G1 = `${fieldWord(G1_X)}${fieldWord(G1_Y)}`;
const OFF_CURVE_G1 = `${fieldWord(G1_X)}${fieldWord(`${G1_Y.slice(0, -1)}0`)}`;
const FINALITY = JSON.parse(fs.readFileSync(
  path.resolve(__dirname, "..", "..", "fixtures", "sccp", "finality_v1.json"), "utf8"));

function open(hardfork, options = {}) {
  return createNativeEdrProvider({ chainId: 1, blockGasLimit: 60_000_000, hardfork, ...options });
}

function call(provider, to, data, gas = 1_000_000) {
  return provider.request({ method: "eth_call", params: [{ to, data: `0x${data}`, gas: `0x${gas.toString(16)}` }, "latest"] });
}

// Runtime that forwards its calldata to `precompile` with `gas()` and returns
// (success, returndatasize, gas spent by the call).
function forwarder(precompile) {
  return `0x3660006000375a6000600036600060${precompile.slice(-2)}5afa5a9060005290036040523d60205260606000f3`;
}

test("revert assertions accept exact native bytes and reject unrelated RPC failures", () => {
  const encoded = `0x08c379a0${AbiCoder.defaultAbiCoder().encode(["string"], ["SC_BREAKER"]).slice(2)}`;
  const native = { code: -32000, data: { data: encoded, reason: { Revert: encoded } } };
  assert(rejectedWith("SC_BREAKER")({ error: native }));
  assert(rejectedWith("SC_BREAKER")({ code: "CALL_EXCEPTION", data: encoded }));
  assert(rejectedWith()(native));
  assert(!rejectedWith("other")(native));
  assert(!rejectedWith("SC_BREAKER")({ code: -32000, message: "SC_BREAKER revert" }));
  assert(!rejectedWith()({ code: -32000, data: { data: encoded, reason: { OutOfGas: encoded } } }));
  assert(!rejectedWith()({ code: -32000, data: { data: encoded, reason: { Revert: "0x" } } }));
  assert(!rejectedWith("SC_BREAKER")({ code: "CALL_EXCEPTION", data: `${encoded}00` }));
  assert(!rejectedWith()({ code: "CALL_EXCEPTION", data: "0x1" }));
});

test("native EDR rejects malformed limits and requests", async () => {
  assert.throws(() => createNativeEdrProvider({ chainId: 0, blockGasLimit: 20_000_000, hardfork: "osaka" }));
  assert.throws(() => createNativeEdrProvider({ chainId: 1, blockGasLimit: NaN, hardfork: "osaka" }));
  const provider = createNativeEdrProvider({ chainId: 56, blockGasLimit: 20_000_000, hardfork: "osaka" });
  try {
    await assert.rejects(provider.request({ method: "eth_chainId", params: {} }));
    await assert.rejects(provider.request({ method: "unavailable_sccp_method" }),
      (error) => Number.isInteger(error.code));
  } finally {
    await provider.disconnect();
  }
  await assert.rejects(provider.request({ method: "eth_chainId" }), /disconnected/);
});

test("native EDR keeps chain identity, balances and mined state isolated", async () => {
  const first = createNativeEdrProvider({ chainId: 56, blockGasLimit: 20_000_000, hardfork: "osaka" });
  const second = createNativeEdrProvider({ chainId: 1, blockGasLimit: 20_000_000, hardfork: "prague" });
  try {
    assert.equal(await first.request({ method: "eth_chainId" }), "0x38");
    assert.equal(await second.request({ method: "eth_chainId" }), "0x1");
    const [sender, recipient] = await first.request({ method: "eth_accounts" });
    const initial = await second.request({ method: "eth_getBalance", params: [recipient, "latest"] });
    const hash = await first.request({ method: "eth_sendTransaction", params: [{ from: sender, to: recipient, value: "0x123" }] });
    const receipt = await first.request({ method: "eth_getTransactionReceipt", params: [hash] });
    assert.equal(receipt.status, "0x1");
    assert.equal(await second.request({ method: "eth_getBalance", params: [recipient, "latest"] }), initial);
    assert.equal(BigInt(await first.request({ method: "eth_getBalance", params: [recipient, "latest"] })), BigInt(initial) + 0x123n);
    assert.equal(await first.request({ method: "eth_blockNumber" }), "0x1");
    assert.equal(await second.request({ method: "eth_blockNumber" }), "0x0");
  } finally {
    await first.disconnect();
    await second.disconnect();
  }
});

test("native EDR reports mined reverts and enforces the contract-size ceiling", async () => {
  const provider = createNativeEdrProvider({ chainId: 56, blockGasLimit: 20_000_000, hardfork: "osaka" });
  try {
    const [sender] = await provider.request({ method: "eth_accounts" });
    await assert.rejects(provider.request({ method: "eth_sendTransaction", params: [{
      from: sender, data: "0x60006000fd", gas: "0x186a0",
    }] }), (error) => Number.isInteger(error.code) && /revert/i.test(error.message));
    assert.equal(await provider.request({ method: "eth_getTransactionCount", params: [sender, "latest"] }), "0x1");
    assert.equal(await provider.request({ method: "eth_blockNumber" }), "0x1");
    const oversized = `0x61600161000f6000396160016000f3${"00".repeat(24_577)}`;
    await assert.rejects(provider.request({ method: "eth_sendTransaction", params: [{
      from: sender, data: oversized, gas: "0xf42400",
    }] }), (error) => Number.isInteger(error.code) && /code.*(large|size)/i.test(error.message));
  } finally {
    await provider.disconnect();
  }
});

test("uncached native state reads observe changed revert reasons immediately", async () => {
  const provider = createNativeEdrProvider({ chainId: 56, blockGasLimit: 20_000_000, hardfork: "osaka" });
  const ethereum = new BrowserProvider(provider, undefined, { cacheTimeout: -1 });
  try {
    const signer = await ethereum.getSigner();
    const address = "0x0000000000000000000000000000000000000123";
    for (const reason of ["SC_REPLAY", "SC_BREAKER"]) {
      const encoded = `08c379a0${AbiCoder.defaultAbiCoder().encode(["string"], [reason]).slice(2)}`;
      const length = (encoded.length / 2).toString(16).padStart(2, "0");
      const code = `0x60${length}600c60003960${length}6000fd${encoded}`;
      await provider.request({ method: "hardhat_setCode", params: [address, code] });
      await assert.rejects(signer.estimateGas({ to: address, data: "0x1234" }), rejectedWith(reason));
    }
  } finally {
    await provider.disconnect();
  }
});

test("native EDR refuses an unknown hardfork and a malformed same-timestamp option", () => {
  for (const hardfork of [undefined, "", "cancun", "Prague", "OSAKA", "fusaka", 19, null]) {
    assert.throws(() => createNativeEdrProvider({ chainId: 1, blockGasLimit: 20_000_000, hardfork }),
      /hardfork "prague" or "osaka"/);
  }
  for (const allowBlocksWithSameTimestamp of [1, "true", null]) {
    assert.throws(() => open("prague", { allowBlocksWithSameTimestamp }), /must be a boolean/);
  }
});

test("native EDR applies the rules of the requested hardfork", async () => {
  // EIP-7825 (Osaka) caps one transaction at 2^24 gas; Prague has no cap.
  const overCap = `0x${(2 ** 24 + 1).toString(16)}`;
  const prague = open("prague");
  const osaka = open("osaka");
  try {
    assert.equal(prague.hardfork, "prague");
    assert.equal(osaka.hardfork, "osaka");
    const [sender] = await prague.request({ method: "eth_accounts" });
    const hash = await prague.request({ method: "eth_sendTransaction", params: [{ from: sender, to: sender, gas: overCap }] });
    assert.equal((await prague.request({ method: "eth_getTransactionReceipt", params: [hash] })).status, "0x1");
    await assert.rejects(osaka.request({ method: "eth_sendTransaction", params: [{ from: sender, to: sender, gas: overCap }] }),
      /exceeds transaction gas cap of 16777216/);
    const atCap = await osaka.request({ method: "eth_sendTransaction", params: [{ from: sender, to: sender, gas: "0x1000000" }] });
    assert.equal((await osaka.request({ method: "eth_getTransactionReceipt", params: [atCap] })).status, "0x1");
  } finally {
    await prague.disconnect();
    await osaka.disconnect();
  }
});

test("native EDR exposes the EIP-2537 precompiles at prague and osaka", async () => {
  const certificate = FINALITY.certificates.find((entry) => entry.label === "n4_lowest_q");
  assert(certificate, "finality_v1.json must contain the certificate n4_lowest_q");
  const pairing = certificate.pairing_input.slice(2);
  assert.equal(pairing.length, 2 * 768, "pairing input is apk, Q, -g1, sigma");
  assert.equal(pairing.slice(0, 256), certificate.aggregate_public_key.eip2537.slice(2));
  assert.equal(pairing.slice(256, 768), certificate.hash_to_g2_m.eip2537.slice(2));
  assert.equal(pairing.slice(768, 896), fieldWord(G1_X));
  assert.equal(pairing.slice(1024), certificate.aggregate_signature.eip2537.slice(2));
  // Replacing -g1 by g1 keeps every point valid and breaks only the pairing equation.
  const negatedY = BigInt(`0x${pairing.slice(896, 1024)}`);
  assert.equal((FIELD_MODULUS - negatedY).toString(16).padStart(96, "0"), G1_Y);
  const unequal = `${pairing.slice(0, 768)}${G1}${pairing.slice(1024)}`;
  const results = {};
  for (const hardfork of HARDFORKS) {
    const provider = open(hardfork);
    try {
      const doubled = await call(provider, G1ADD, `${G1}${G1}`);
      assert.equal(doubled.length, 2 + 2 * 128, "G1ADD returns one 128-byte G1 point");
      assert.notEqual(doubled, `0x${G1}`);
      assert.equal(await call(provider, G1ADD, `${G1}${"00".repeat(128)}`), `0x${G1}`, "infinity is the identity");
      const mapped = await call(provider, MAP_FP2_TO_G2, "00".repeat(128));
      assert.equal(mapped.length, 2 + 2 * 256, "MAP_FP2_TO_G2 returns one 256-byte G2 point");
      assert.equal(await call(provider, PAIRING_CHECK, pairing), `0x${"00".repeat(31)}01`);
      assert.equal(await call(provider, PAIRING_CHECK, unequal), `0x${"00".repeat(32)}`);
      for (const [precompile, input, reason] of [
        [G1ADD, `${G1}${OFF_CURVE_G1}`, /not on curve/],
        [G1ADD, G1, /input length/],
        [MAP_FP2_TO_G2, `${"00".repeat(64)}${fieldWord(FIELD_MODULUS.toString(16))}`, /./],
        [PAIRING_CHECK, `${OFF_CURVE_G1}${pairing.slice(256)}`, /not on curve/],
        [PAIRING_CHECK, "", /./],
      ]) {
        await assert.rejects(call(provider, precompile, input),
          (error) => error.code === -32000 && error.data.data === "0x" && reason.test(error.message));
      }
      results[hardfork] = [doubled, mapped];
    } finally {
      await provider.disconnect();
    }
  }
  assert.deepEqual(results.prague, results.osaka);
});

test("a failing EIP-2537 precompile burns the gas a contract forwards to it", async () => {
  const caller = "0x00000000000000000000000000000000000000aa";
  const word = (result, index) => BigInt(`0x${result.slice(2 + 64 * index, 66 + 64 * index)}`);
  for (const hardfork of HARDFORKS) {
    const provider = open(hardfork);
    try {
      await provider.request({ method: "hardhat_setCode", params: [caller, forwarder(G1ADD)] });
      const valid = await call(provider, caller, `${G1}${G1}`);
      assert.deepEqual([word(valid, 0), word(valid, 1)], [1n, 128n]);
      assert(word(valid, 2) < 1_000n, "a successful G1ADD costs its fixed price");
      const invalid = await call(provider, caller, `${G1}${OFF_CURVE_G1}`);
      assert.deepEqual([word(invalid, 0), word(invalid, 1)], [0n, 0n], "failure returns no data");
      // 63/64 of the gas left at the call is forwarded and none of it comes back.
      assert(word(invalid, 2) > 900_000n, `forwarded gas must be consumed, spent ${word(invalid, 2)}`);
    } finally {
      await provider.disconnect();
    }
  }
});

test("same-timestamp blocks are mined only on request and time never decreases", async () => {
  const latest = async (provider) => provider.request({ method: "eth_getBlockByNumber", params: ["latest", false] });
  const mineAt = async (provider, timestamp) => {
    await provider.request({ method: "evm_setNextBlockTimestamp", params: [`0x${timestamp.toString(16)}`] });
    await provider.request({ method: "evm_mine", params: [] });
    return latest(provider);
  };
  for (const hardfork of HARDFORKS) {
    const strict = open(hardfork);
    const repeating = open(hardfork, { allowBlocksWithSameTimestamp: true });
    try {
      assert.equal(strict.allowBlocksWithSameTimestamp, false);
      const genesis = BigInt((await latest(strict)).timestamp);
      await assert.rejects(mineAt(strict, genesis), /equal to the previous block's timestamp/);
      assert.equal((await mineAt(strict, genesis + 1n)).timestamp, `0x${(genesis + 1n).toString(16)}`);
      for (const number of ["0x1", "0x2"]) {
        const block = await mineAt(repeating, genesis);
        assert.deepEqual([block.number, BigInt(block.timestamp)], [number, genesis]);
      }
      await assert.rejects(mineAt(repeating, genesis - 1n), /lower than the previous block's timestamp/);
      assert.equal((await latest(repeating)).number, "0x2");
    } finally {
      await strict.disconnect();
      await repeating.disconnect();
    }
  }
});
