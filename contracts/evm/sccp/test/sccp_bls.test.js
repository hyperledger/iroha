"use strict";

// EDR suite for `contracts/evm/sccp/lib/BLS12_381.sol` (`specs/sccp.md` §3.8,
// §5.2.4, §11.5): RFC 9380 hash-to-G2 under `DST_SIG`, G1 addition and the
// two-pair pairing check over the EIP-2537 precompiles. The library is
// exercised through `test/harness/SccpBlsHarness.sol`, compiled with the pinned
// compiler and the locked settings, under both the Prague and the Osaka rules.
// Expected values come from the shared Python and Rust BLS/finality fixtures
// and, for digests the fixtures do not list, from `@noble/curves`; nothing is
// compared with the library's own output. Every applicable signature and
// fast-aggregate row is replayed, including malformed coordinates and the
// captured Ethereum sync committee. The ledger distinguishes executed rows
// from APIs the destination does not expose, and pins coverage floors.
//
// Run: `node --test contracts/evm/sccp/test/sccp_bls.test.js` with the locked
// EVM runtime installed (`npm ci --ignore-scripts` in
// `scripts/contract_tooling/evm-runtime`, or `SCCP_EVM_RUNTIME_DIR` /
// `NODE_PATH` naming an installed copy). `SCCP_CORRIDOR_PYTHON_BIN` selects
// the Python that runs the artifact corridor (developer convenience).

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { createRequire } = require("node:module");
const { after, before, describe, it } = require("node:test");
const m = require("./sccp_v1_model.js");
const h = require("./sccp_edr_harness.js");
const { Ledger } = require("./sccp_replay.js");

const { ethers, REPO, RUNTIME_DIR } = m;
const { bls12_381: noble } = createRequire(path.join(RUNTIME_DIR, "package.json"))("@noble/curves/bls12-381");

const LIBRARY_SOURCE = "contracts/evm/sccp/lib/BLS12_381.sol";
const HARNESS_SOURCE = "contracts/evm/sccp/test/harness/SccpBlsHarness.sol";
const HARDFORKS = ["prague", "osaka"];
const PROFILE = Object.freeze({ name: "ethereum", chainId: 1n });
const BLS = JSON.parse(fs.readFileSync(path.join(REPO, "fixtures", "sccp", "bls_consensus_v1.json"), "utf8"));
const BLS_RUST = JSON.parse(fs.readFileSync(path.join(REPO, "fixtures", "sccp", "bls_consensus_rust_v1.json"), "utf8"));
const MALFORMED = BLS.ethereum_malformed_inputs;
const FINALITY = JSON.parse(fs.readFileSync(path.join(REPO, "fixtures", "sccp", "finality_v1.json"), "utf8"));
const FINALITY_RUST = JSON.parse(fs.readFileSync(path.join(REPO, "fixtures", "sccp", "finality_rust_v1.json"), "utf8"));

const DST_SIG = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
const P = noble.fields.Fp.ORDER;
const HALF_P = (P - 1n) / 2n;
const G2ADD = "0x000000000000000000000000000000000000000d";
const MAP_FP2_TO_G2 = "0x0000000000000000000000000000000000000011";
// Below the EIP-7825 transaction gas cap of 2^24 that Osaka applies.
const CALL_GAS = 16_000_000n;
// A refused precompile input consumes the gas forwarded to it, 63/64 of what
// is left, so refusals are probed with a smaller allowance.
const REFUSAL_GAS = 1_000_000n;
// Memory fills: (words written from the free memory pointer on, the word
// written). Hash-to-G2 allocates and uses as temporary memory 35 words, so a
// fill of 64 words or more covers all of it and the one-word fill only the
// start of its result.
const CLEAN = [0, `0x${"00".repeat(32)}`];
const FULL_FILLS = [
  [64, `0x${"ff".repeat(32)}`],
  [257, `0x${"01".repeat(32)}`],
  [4096, `0x${"a5".repeat(32)}`],
];
const DIRTY = [[1, `0x${"ff".repeat(32)}`], ...FULL_FILLS];
const PANIC_ASSERT = ethers.concat([ethers.id("Panic(uint256)").slice(0, 10), ethers.toBeHex(1, 32)]);

// Gas of the library call alone on clean memory (`gasleft()` around it in the
// harness), measured on EDR 0.12.1 with the locked build. A run above 1.1 × a
// recorded value fails, the rule of §5.4. Osaka prices each of the four MODEXP
// field reductions of hash-to-G2 at 500 gas instead of 200 (EIP-7883).
const RECORDED_GAS = Object.freeze({
  prague: Object.freeze({ hashToField: 5_278n, hashToG2: 54_036n, pairingCheck: 103_124n, g1Add: 591n }),
  osaka: Object.freeze({ hashToField: 6_478n, hashToG2: 55_236n, pairingCheck: 103_124n, g1Add: 591n }),
});
const MODEXP_REPRICING = 4n * 300n;

// Each group is enumerated independently of its replay loop. Counts are floors:
// newly generated rows are replayed automatically, while removing rows fails.
const BLS_ROWS = Object.freeze({
  "ethereum_malformed_inputs.g1_deserialization": [MALFORMED.g1_deserialization.filter((row) => row.evm_affine_pairing !== null), 13],
  "ethereum_malformed_inputs.g2_deserialization": [MALFORMED.g2_deserialization.filter((row) => row.evm_affine_pairing !== null), 15],
  "hash_to_g2_dst_sig": [BLS.hash_to_g2_dst_sig, 4],
  "sign_verify.signatures": [BLS.sign_verify.signatures, 6],
  "sign_verify.negatives": [BLS.sign_verify.negatives, 15],
  "aggregates.fast_aggregate_verify": [BLS.aggregates.fast_aggregate_verify, 10],
  "ethereum_standard_inputs.signatures": [BLS.ethereum_standard_inputs.signatures, 9],
  "ethereum_standard_inputs.fast_aggregates": [BLS.ethereum_standard_inputs.fast_aggregates, 3],
  "ethereum_mainnet_sync_committee": [[BLS.ethereum_mainnet_sync_committee,
    BLS.ethereum_mainnet_sync_committee.negative_first_participant_dropped], 2],
  "rust.standard_vectors.verify": [BLS_RUST.standard_vectors.verify, 27],
  "rust.standard_vectors.fast_aggregate_verify": [BLS_RUST.standard_vectors.fast_aggregate_verify, 9],
  "rust.negatives": [BLS_RUST.negatives, 21],
});

// These APIs are not exposed by the destination. Record the reason and count
// separately from executed rows: no skipped row is counted as a contract call.
const BLS_SKIPS = Object.freeze({
  "ethereum_malformed_inputs.g1_compressed_lengths": [MALFORMED.g1_deserialization.filter((row) => row.evm_affine_pairing === null), 3, "wrong compressed lengths have no EIP-2537 affine encoding; Rust and TON exercise them"],
  "ethereum_malformed_inputs.g2_compressed_lengths": [MALFORMED.g2_deserialization.filter((row) => row.evm_affine_pairing === null), 3, "wrong compressed lengths have no EIP-2537 affine encoding; Rust and TON exercise them"],
  "sign_verify.keys": [BLS.sign_verify.keys, 3, "key generation; public keys are used by verification"],
  "aggregates.aggregate_verify": [BLS.aggregates.aggregate_verify, 3, "distinct-message aggregation"],
  "ethereum_standard_inputs.privkeys": [BLS.ethereum_standard_inputs.privkeys, 3, "key generation and signing"],
  "ethereum_standard_inputs.aggregate_verify": [[BLS.ethereum_standard_inputs.aggregate_verify], 1, "distinct-message aggregation"],
  "consensus_allowlist": [BLS.consensus_allowlist, 32, "Rust-only consensus-preimage allowlist API"],
  "imported_rfc9380.expand_message_xmd": [BLS.imported_rfc9380.expand_message_xmd.vectors, 10, "generic-message RFC suite has another DST; destination hashes a 32-byte digest under DST_SIG"],
  "imported_rfc9380.hash_to_g2": [BLS.imported_rfc9380.hash_to_g2.vectors, 5, "generic-message RFC suite has another DST; destination hashes a 32-byte digest under DST_SIG"],
  "rust.keys": [BLS_RUST.keys, 3, "key generation and w3f PoP generation; public keys are used by verification"],
  "rust.allowlist": [BLS_RUST.allowlist, 8, "Rust-only consensus-preimage allowlist API"],
  "rust.allowlist_rejections": [BLS_RUST.allowlist_rejections, 34, "Rust-only consensus-preimage allowlist API"],
  "rust.standard_vectors.sign": [BLS_RUST.standard_vectors.sign, 9, "signing; these signatures are replayed by standard_vectors.verify"],
  "rust.standard_vectors.aggregate": [BLS_RUST.standard_vectors.aggregate, 3, "signature generation/aggregation; resulting signatures are replayed by fast_aggregate_verify"],
  "rust.standard_vectors.aggregate_verify": [BLS_RUST.standard_vectors.aggregate_verify, 2, "distinct-message aggregation"],
});

const fixtureRowId = (entry, index) => `${index}:${entry.label ?? entry.case ?? "row"}`;

// ---------------------------------------------------------------------------
// Encodings
// ---------------------------------------------------------------------------

const size = (value) => ethers.dataLength(value);
const slice = (value, start, end) => ethers.dataSlice(value, start, end);
const zeros = (length) => `0x${"00".repeat(length)}`;

/** 64-byte EIP-2537 field element of an integer below 2^512. */
function fieldElement(value) {
  return ethers.toBeHex(BigInt(value), 64);
}

/** `(hi, lo)` word pair of a 48-byte value: its upper 16 and lower 32 bytes. */
function wordPair(value) {
  const number = BigInt(value);
  return [number >> 256n, number & ((1n << 256n) - 1n)];
}

/** Zero-extends every 48-byte limb to a 64-byte field element (§3.7). */
function expandLimbs(limbs) {
  assert.equal(size(limbs) % 48, 0, "limbs are 48 bytes each");
  const parts = [];
  for (let offset = 0; offset < size(limbs); offset += 48) parts.push(zeros(16), slice(limbs, offset, offset + 48));
  return ethers.concat(parts);
}

/** EIP-2537 form of an affine G2 point of `@noble/curves`. */
function g2Bytes(point) {
  const { x, y } = point.toAffine();
  return ethers.concat([fieldElement(x.c0), fieldElement(x.c1), fieldElement(y.c0), fieldElement(y.c1)]);
}

/** EIP-2537 form of a G1 point of `@noble/curves` (the identity is 128 zero bytes). */
function g1Bytes(point) {
  if (point.equals(noble.G1.ProjectivePoint.ZERO)) return zeros(128);
  const { x, y } = point.toAffine();
  return ethers.concat([fieldElement(x), fieldElement(y)]);
}

/**
 * Translates a fixture's compressed point to the affine EIP-2537 ABI without
 * performing the subgroup check in JavaScript. Malformed field values remain
 * unreduced; off-curve x coordinates get y = 0, so the actual precompile refuses
 * them. Flag-only errors have no affine representation: the helper sees the
 * same point. This is deliberately not a compressed-point verifier, and the
 * tests below distinguish its arithmetic result from certificate admission.
 */
function fixtureAffine(compressed, group) {
  const bytes = ethers.getBytes(compressed);
  assert.equal(bytes.length, group === 1 ? 48 : 96, "fixture compressed-point length");
  const infinity = (bytes[0] & 0x40) !== 0;
  const sign = (bytes[0] & 0x20) !== 0;
  bytes[0] &= 0x1f;
  if (group === 1) {
    const x = BigInt(ethers.hexlify(bytes));
    let y = 0n;
    if (!infinity && x < P) {
      try {
        y = noble.fields.Fp.sqrt(noble.fields.Fp.add(noble.fields.Fp.pow(x, 3n), 4n));
        if ((y > HALF_P) !== sign) y = P - y;
      } catch { /* Preserve the invalid x with y = 0 for the precompile. */ }
    }
    return ethers.concat([fieldElement(x), fieldElement(y)]);
  }
  const x = { c0: BigInt(ethers.hexlify(bytes.slice(48))), c1: BigInt(ethers.hexlify(bytes.slice(0, 48))) };
  let y = { c0: 0n, c1: 0n };
  const fp2 = noble.fields.Fp2;
  if (!infinity && x.c0 < P && x.c1 < P) {
    try {
      y = fp2.sqrt(fp2.add(fp2.pow(x, 3n), noble.params.G2b));
      if (((y.c1 === 0n ? y.c0 : y.c1) > HALF_P) !== sign) y = fp2.neg(y);
    } catch { /* Preserve invalid coordinates for the precompile. */ }
  }
  return ethers.concat([fieldElement(x.c0), fieldElement(x.c1), fieldElement(y.c0), fieldElement(y.c1)]);
}

/** Replays aggregation, hash-to-G2 and pairing through the deployed library. */
async function replayVerification(bench, keys, message, signature, expected, label, aggregatePoint) {
  assert.equal(size(message), 32, `${label}: destination message is a digest`);
  if (keys.length === 0) {
    assert.equal(expected, false, `${label}: empty key list`);
    await expectRevertData(bench.call("g1Sum", ["0x", ...CLEAN]), "0x", label);
    return;
  }
  const points = keys.map((key) => fixtureAffine(key, 1));
  const aggregate = await bench.g1Sum(points, CLEAN, REFUSAL_GAS);
  if (!aggregate.ok) {
    assert.equal(expected, false, `${label}: EIP-2537 G1ADD refused the key`);
    return;
  }
  if (aggregatePoint !== undefined) assert.equal(aggregate.sum, aggregatePoint, `${label}: aggregate key`);
  const q = await bench.hashToG2(message);
  const negG1 = FINALITY.constants.bls12_381.neg_g1.eip2537;
  const sigma = fixtureAffine(signature, 2);
  const result = await bench.pairingCheck(ethers.concat([aggregate.sum, q, negG1, sigma]), CLEAN, REFUSAL_GAS);
  assert.equal(result.ok, expected, `${label}: EIP-2537 affine pairing outcome`);
}

/**
 * The 128-byte G1 points of the signers of a fixture certificate, in ascending
 * index order, built from its EVM wire form as §3.7 states: `x` is the
 * committee key with the three flag bits cleared, `y` comes from `signerYs`.
 */
function signerPoints(certificate) {
  const { qc, committee, signerYs } = certificate.evm;
  assert.equal(size(qc), 116, `${certificate.label}: QC_FIXED length`);
  const signers = BigInt(slice(qc, 112, 116));
  const points = [];
  for (let index = 0; index < 32; index += 1) {
    if (((signers >> BigInt(index)) & 1n) === 0n) continue;
    const key = ethers.getBytes(slice(committee, 48 * index, 48 * index + 48));
    key[0] &= 0x1f;
    const y = slice(signerYs, 48 * points.length, 48 * points.length + 48);
    points.push(ethers.concat([zeros(16), key, zeros(16), y]));
  }
  assert.equal(48 * points.length, size(signerYs), `${certificate.label}: one y per signer`);
  return points;
}

function row(rows, label) {
  const found = rows.filter((entry) => entry.label === label);
  assert.equal(found.length, 1, `fixture row ${label}`);
  return found[0];
}

const positive = (label) => row(FINALITY.certificates, label);
const negative = (label) => row(FINALITY.negative_certificates, label);

// ---------------------------------------------------------------------------
// Builds and chains
// ---------------------------------------------------------------------------

// The two lines of `hashToField` that write `Z_pad`. They store zeros, so a
// build without them still passes on fresh memory; only the dirty-memory runs
// tell the two builds apart.
const Z_PAD_WRITES = [
  "            mstore(s, 0) // Z_pad: one SHA-256 block of zero bytes\n",
  "            mstore(add(s, 0x20), 0)\n",
].join("");

// An address with no code and no precompile under either hardfork: a call to
// it succeeds and returns nothing, which is what a call to an EIP-2537 address
// does on a chain that lacks the precompile. The builds below move the named
// precompiles there, so that only the return-length check stands between the
// library and a result read from whatever memory held before.
const EMPTY_ACCOUNT = "0xee";
const MOVED_PRECOMPILES = Object.freeze({
  "without-eip-2537": ["G1ADD", "G2ADD", "PAIRING_CHECK", "MAP_FP2_TO_G2"],
  "without-g2add": ["G2ADD"],
  "without-modexp": ["MODEXP"],
  "without-sha256": ["SHA256"],
});

/** The library source of a build: null for the checkout's, else the named variant of it. */
function librarySource(kind) {
  if (kind === "library") return null;
  let source = fs.readFileSync(path.join(REPO, LIBRARY_SOURCE), "utf8");
  if (kind === "without-z-pad") {
    assert.equal(source.split(Z_PAD_WRITES).length, 2, "the library writes Z_pad exactly once, in the pinned form");
    return source.replace(Z_PAD_WRITES, "");
  }
  assert(Object.hasOwn(MOVED_PRECOMPILES, kind), `unknown build ${kind}`);
  for (const name of MOVED_PRECOMPILES[kind]) {
    const declaration = new RegExp(`(uint256 private constant PRECOMPILE_${name} = )0x[0-9a-f]{2};`, "g");
    assert.equal((source.match(declaration) ?? []).length, 1, `one declaration of PRECOMPILE_${name}`);
    source = source.replace(declaration, `$1${EMPTY_ACCOUNT};`);
  }
  return source;
}

const builds = new Map();

/** The compiled harness over the checkout's library (`library`) or over a variant of it. */
function build(kind) {
  if (!builds.has(kind)) {
    const source = librarySource(kind);
    const overrides = source === null ? {} : { [LIBRARY_SOURCE]: source };
    builds.set(kind, h.compileTestSources([LIBRARY_SOURCE, HARNESS_SOURCE], overrides));
  }
  return builds.get(kind);
}

/** One deployed `SccpBlsHarness` on an EDR chain. */
class Bench {
  static async deploy(chain, kind) {
    const artifact = build(kind)[HARNESS_SOURCE].SccpBlsHarness;
    const receipt = await chain.send({ data: `0x${artifact.evm.bytecode.object}` });
    return new Bench(chain, ethers.getAddress(receipt.contractAddress), new ethers.Interface(artifact.abi));
  }

  constructor(chain, address, iface) {
    this.chain = chain;
    this.address = address;
    this.iface = iface;
  }

  /** `eth_call` of one harness function with an explicit gas allowance; returns the decoded result. */
  async call(name, args, gas = CALL_GAS) {
    const request = { to: this.address, data: this.iface.encodeFunctionData(name, args), gas: ethers.toQuantity(gas) };
    return this.iface.decodeFunctionResult(name, await this.chain.rpc("eth_call", [request, "latest"]));
  }

  /** `eth_call` straight to a precompile. */
  precompile(address, data) {
    return this.chain.rpc("eth_call", [{ to: address, data, gas: ethers.toQuantity(CALL_GAS) }, "latest"]);
  }

  async hashToG2(digest, fill = CLEAN) {
    return (await this.call("hashToG2", [digest, ...fill]))[0];
  }

  async hashToField(digest, fill = CLEAN) {
    return (await this.call("hashToField", [digest, ...fill]))[0];
  }

  /** Aggregates 128-byte points; returns `{ ok, sum, infinity, gasUsed }`. */
  async g1Sum(points, fill = CLEAN, gas = CALL_GAS) {
    const [ok, pair, infinity, gasUsed] = await this.call("g1Sum", [ethers.concat(points), ...fill], gas);
    return { ok, sum: slice(pair, 0, 128), infinity, gasUsed };
  }

  /** Returns `{ ok, gasUsed }` of the pairing check over a 768-byte input. */
  async pairingCheck(input, fill = CLEAN, gas = CALL_GAS) {
    const [ok, gasUsed] = await this.call("pairingCheck", [input, ...fill], gas);
    return { ok, gasUsed };
  }
}

/** Requires `promise` to fail with exactly `expected` as revert data. */
async function expectRevertData(promise, expected, label) {
  let failure = null;
  try {
    await promise;
  } catch (error) {
    failure = error;
  }
  assert(failure, `${label}: expected a revert, but the call succeeded`);
  assert.equal(h.revertData(failure), expected, `${label}: ${failure.message}`);
}

/** A refusal consumed the gas forwarded to the precompile, 63/64 of what the caller had. */
function assertRefusalGas(gasUsed, label) {
  assert(gasUsed > (REFUSAL_GAS * 9n) / 10n, `${label}: a refused input consumes the forwarded gas (${gasUsed})`);
}

// ---------------------------------------------------------------------------
// Source rules (§5.2.4, §5.5)
// ---------------------------------------------------------------------------

describe("BLS12_381 source and build", () => {
  const source = fs.readFileSync(path.join(REPO, LIBRARY_SOURCE), "utf8");
  const code = source.replace(/\/\/.*$/gm, "");

  it("compiles with solc 0.8.31, cancun and the legacy pipeline without any diagnostic", () => {
    const lockPath = path.join(REPO, "scripts", "contract_tooling", "compiler-lock.json");
    const lock = JSON.parse(fs.readFileSync(lockPath, "utf8"));
    assert.equal(lock.compilers.evm.reported_version, "0.8.31+commit.fd3a2265");
    assert.equal(lock.settings.evmVersion, "cancun");
    assert.equal(lock.settings.viaIR, false);
    // `compileTestSources` fails on any diagnostic, warnings included.
    const contracts = build("library");
    const library = contracts[LIBRARY_SOURCE].BLS12_381;
    const harness = contracts[HARNESS_SOURCE].SccpBlsHarness;
    // Internal functions only: nothing to call and nothing to link.
    assert.deepEqual(library.abi, []);
    assert.deepEqual(harness.evm.bytecode.linkReferences, {});
    assert.deepEqual(harness.evm.deployedBytecode.linkReferences ?? {}, {});
    assert.deepEqual(harness.evm.deployedBytecode.immutableReferences ?? {}, {});
  });

  it("meets the corridor source policy and imports nothing", () => {
    assert(source.startsWith("// SPDX-License-Identifier: Apache-2.0\npragma solidity 0.8.31;\n"));
    assert.deepEqual(code.match(/\bpragma\b[^;]*;/g), ["pragma solidity 0.8.31;"]);
    for (const banned of [/\bimport\b/, /\bdelete\b/, /\blayout\s+at\b/, /\bpublic\b/, /\bexternal\b/]) {
      assert(!banned.test(code), `the library must not contain ${banned}`);
    }
    assert.deepEqual(code.match(/\b(library|contract|interface)\s+\w+/g), ["library BLS12_381"]);
  });

  it("calls only the six precompiles, always with gas() and a checked return length", () => {
    const declared = code.matchAll(/uint256 private constant (PRECOMPILE_\w+) = (0x[0-9a-f]{2});/g);
    const precompiles = new Map([...declared].map((entry) => [entry[1], entry[2]]));
    assert.deepEqual(Object.fromEntries(precompiles), {
      PRECOMPILE_SHA256: "0x02",
      PRECOMPILE_MODEXP: "0x05",
      PRECOMPILE_G1ADD: "0x0b",
      PRECOMPILE_G2ADD: "0x0d",
      PRECOMPILE_PAIRING_CHECK: "0x0f",
      PRECOMPILE_MAP_FP2_TO_G2: "0x11",
    });
    // BSC's own BLS precompile is never a target (§5.2.4 "Not used").
    assert(!/0x66\b/.test(code));
    // Every call is a staticcall that forwards gas() to a named precompile.
    const calls = code.match(/\b(?:static|delegate)?call(?:code)?\s*\(/g) ?? [];
    const forwarded = code.match(/\bstaticcall\(gas\(\), PRECOMPILE_\w+, /g) ?? [];
    assert.equal(calls.length, 8);
    assert.equal(forwarded.length, calls.length);
    assert.deepEqual(
      [...new Set(forwarded.map((entry) => entry.match(/PRECOMPILE_\w+/)[0]))].sort(),
      [...precompiles.keys()].sort(),
    );
    // Each call keeps its success flag, and the flag is used together with the
    // exact return length; the pairing check also requires the value 1.
    const kept = code.match(/\bok := staticcall\(gas\(\), PRECOMPILE_\w+, /g) ?? [];
    const checked = code.match(/\band\(ok, (?:and\()?eq\(returndatasize\(\), 0x[0-9a-f]+\)/g) ?? [];
    assert.equal(kept.length, calls.length);
    assert.equal(checked.length, calls.length);
    assert.equal((code.match(/\beq\(returndatasize\(\), /g) ?? []).length, calls.length);
    assert.equal((code.match(/\band\(eq\(returndatasize\(\), 0x20\), eq\(mload\(0x00\), 1\)\)/g) ?? []).length, 1);
    assert(!/\bgas\s*:/.test(code));
  });

  it("fails a test-only compilation on any compiler diagnostic and on a stray override", () => {
    const harness = fs.readFileSync(path.join(REPO, HARNESS_SOURCE), "utf8");
    // An unused local variable is a warning, not an error.
    const warned = `${harness}\ncontract Warned {\n    function f() external pure { uint256 unused; }\n}\n`;
    assert.throws(
      () => h.compileTestSources([LIBRARY_SOURCE, HARNESS_SOURCE], { [HARNESS_SOURCE]: warned }),
      /must compile without any diagnostic/,
    );
    assert.throws(
      () => h.compileTestSources([LIBRARY_SOURCE], { [HARNESS_SOURCE]: harness }),
      /override of a source that is not compiled/,
    );
  });

  it("opens a chain only under a named hardfork", async () => {
    await assert.rejects(h.Chain.open(PROFILE), /hardfork/);
    await assert.rejects(h.Chain.open(PROFILE, { hardfork: "cancun" }), /hardfork/);
  });
});

// ---------------------------------------------------------------------------
// Behaviour under both hardforks
// ---------------------------------------------------------------------------

/** Gas measured per hardfork, compared across hardforks after both ran. */
const measured = {};

for (const hardfork of HARDFORKS) {
  describe(`BLS12_381 on EDR (${hardfork})`, () => {
    let chain;
    let bench;
    const ledger = new Ledger();

    before(async () => {
      chain = await h.Chain.open(PROFILE, { hardfork });
      bench = await Bench.deploy(chain, "library");
    });

    after(async () => {
      if (chain) await chain.close();
    });

    it("pins p, HALF_P and −g1 against the fixture and an independent curve implementation", async () => {
      const [p, halfP, negG1, g1Point, g1Pair, g2Point, pairingInput] = await bench.call("constants", []);
      const constants = FINALITY.constants.bls12_381;
      assert.equal(BigInt(constants.p), P);
      assert.equal(BigInt(constants.half_p), HALF_P);
      assert.equal(p, fieldElement(P));
      assert.equal(halfP, fieldElement(HALF_P));
      assert.equal(negG1, constants.neg_g1.eip2537);
      assert.equal(negG1, g1Bytes(noble.G1.ProjectivePoint.BASE.negate()));
      assert.equal(slice(negG1, 0, 64), slice(constants.g1.eip2537, 0, 64));
      assert.equal(BigInt(slice(negG1, 64, 128)), BigInt(constants.neg_g1_y));
      assert.deepEqual([g1Point, g1Pair, g2Point, pairingInput], [128n, 256n, 256n, 768n]);
    });

    it("compares 48-byte values with p and HALF_P at every boundary", async () => {
      const max384 = (1n << 384n) - 1n;
      const low = (1n << 256n) - 1n;
      const [pHi, pLo] = wordPair(P);
      const [halfHi, halfLo] = wordPair(HALF_P);
      const fieldCases = [
        [0n, true],
        [1n, true],
        [P - 1n, true],
        [P, false],
        [P + 1n, false],
        [max384, false],
        [((pHi - 1n) << 256n) | low, true], // smaller upper part, largest lower part
        [(pHi << 256n) | (pLo - 1n), true],
        [(pHi + 1n) << 256n, false], // larger upper part, zero lower part
        [pLo, true], // the lower words alone
        [low, true],
      ];
      for (const [value, expected] of fieldCases) {
        assert.equal((await bench.call("isFieldElement", wordPair(value)))[0], expected, `isFieldElement(${value})`);
        assert.equal(value < P, expected);
      }
      // An upper part that does not fit 16 bytes is never below p.
      assert.equal((await bench.call("isFieldElement", [1n << 128n, 0n]))[0], false);
      assert.equal((await bench.call("isFieldElement", [(1n << 256n) - 1n, 0n]))[0], false);

      const halfCases = [
        [0n, false],
        [HALF_P - 1n, false],
        [HALF_P, false],
        [HALF_P + 1n, true],
        [P - 1n, true],
        [((halfHi - 1n) << 256n) | low, false],
        [(halfHi << 256n) | (halfLo + 1n), true],
        [(halfHi + 1n) << 256n, true],
        [low, false],
      ];
      for (const [value, expected] of halfCases) {
        assert.equal((await bench.call("isAboveHalfP", wordPair(value)))[0], expected, `isAboveHalfP(${value})`);
        assert.equal(value > HALF_P, expected);
      }
      // The ZCash sign bit of every fixture key is exactly `y > HALF_P` (§0).
      assert.equal(FINALITY.test_keys.length, 35);
      const signs = new Set();
      for (const key of FINALITY.test_keys) {
        const sign = (ethers.getBytes(key.pk)[0] & 0x20) !== 0;
        signs.add(sign);
        assert.equal((await bench.call("isAboveHalfP", wordPair(key.pk_y)))[0], sign, `sign of test key ${key.index}`);
        assert.equal((await bench.call("isFieldElement", wordPair(key.pk_y)))[0], true);
      }
      assert.deepEqual([...signs].sort(), [false, true]);
    });

    it("reproduces every hash_to_g2_dst_sig trace: field elements, mapped points and the sum", async () => {
      assert.deepEqual(
        BLS.hash_to_g2_dst_sig.map((trace) => trace.label),
        ["spec_11_2_m", "zero_digest", "sha256_empty", "sha256_sccp"],
      );
      for (const [index, trace] of BLS.hash_to_g2_dst_sig.entries()) {
        // The trace is self-consistent: u_k = OS2IP(uniform_bytes[64k..64k+64]) mod p.
        const elements = [...trace.u0, ...trace.u1].map((value) => BigInt(value));
        assert.equal(size(trace.uniform_bytes), 256);
        elements.forEach((element, k) => {
          assert.equal(BigInt(slice(trace.uniform_bytes, 64 * k, 64 * k + 64)) % P, element, `${trace.label}: u[${k}]`);
        });
        const u = await bench.hashToField(trace.msg);
        assert.equal(u, ethers.concat(elements.map(fieldElement)), `${trace.label}: field elements`);
        assert.equal(slice(u, 0, 128), trace.map_fp2_to_g2_input_u0, `${trace.label}: MAP_FP2_TO_G2 input of u0`);
        assert.equal(slice(u, 128, 256), trace.map_fp2_to_g2_input_u1, `${trace.label}: MAP_FP2_TO_G2 input of u1`);
        // The library's elements, mapped and added by the precompiles, give the trace's points.
        const q0 = await bench.precompile(MAP_FP2_TO_G2, slice(u, 0, 128));
        const q1 = await bench.precompile(MAP_FP2_TO_G2, slice(u, 128, 256));
        assert.equal(q0, trace.map_fp2_to_g2_output_u0, `${trace.label}: mapped u0`);
        assert.equal(q1, trace.map_fp2_to_g2_output_u1, `${trace.label}: mapped u1`);
        assert.equal(await bench.precompile(G2ADD, ethers.concat([q0, q1])), trace.q.eip2537, `${trace.label}: sum`);
        const q = await bench.hashToG2(trace.msg);
        assert.equal(q, trace.q.eip2537, `${trace.label}: hashToG2`);
        assert.equal(q, expandLimbs(trace.q.evm192));
        assert.equal(q, g2Bytes(noble.G2.ProjectivePoint.fromHex(trace.q.compressed.slice(2))));
        assert.equal(fixtureAffine(trace.q.compressed, 2), q, "fixture translation retains the affine point");
        ledger.ran("hash_to_g2_dst_sig", fixtureRowId(trace, index));
      }
    });

    it("replays all sign_verify signatures and negatives with explicit affine-helper outcomes", async () => {
      assert.equal(BLS.sign_verify.dst, DST_SIG);
      for (const [index, entry] of BLS.sign_verify.signatures.entries()) {
        const key = BLS.sign_verify.keys[entry.key].pk;
        assert.equal(fixtureAffine(key, 1), g1Bytes(noble.G1.ProjectivePoint.fromHex(key.slice(2))));
        await replayVerification(bench, [key], entry.msg, entry.signature, entry.verify, `sign_verify.signatures/${index}`);
        ledger.ran("sign_verify.signatures", fixtureRowId(entry, index));
      }
      for (const [index, entry] of BLS.sign_verify.negatives.entries()) {
        // These two rows alter only compressed-point metadata. EIP-2537 takes
        // affine coordinates, so the pairing equation remains valid. The
        // production _checkSignerKey separately rejects a key without its
        // compression flag; the EVM signature ABI has no compression flag.
        const affineOnly = ["pk_missing_compression_flag", "sig_missing_compression_flag"].includes(entry.label);
        if (affineOnly) assert.equal(entry.verify, false, `${entry.label}: compressed API refuses`);
        await replayVerification(bench, [entry.pk], entry.msg, entry.signature,
          affineOnly ? true : entry.verify, `sign_verify.negatives/${entry.label}`);
        ledger.ran("sign_verify.negatives", fixtureRowId(entry, index));
      }
    });

    it("replays every fast aggregate including the arithmetic-only identity-key outcome", async () => {
      for (const [index, entry] of BLS.aggregates.fast_aggregate_verify.entries()) {
        // G1ADD drops O: the arithmetic helper accepts this valid aggregate
        // equation, while certificate admission rejects each identity signer
        // in _checkSignerKey before aggregation. This is NOT destination
        // acceptance of an identity key (covered by finality fixture replays).
        const identityKey = entry.label === "identity_key_in_list";
        if (identityKey) assert.equal(entry.result, false, "compressed API refuses identity signer");
        await replayVerification(bench, entry.pks, entry.msg, entry.signature,
          identityKey ? true : entry.result, `aggregates.fast_aggregate_verify/${entry.label}`,
          entry.aggregate_public_key?.eip2537);
        ledger.ran("aggregates.fast_aggregate_verify", fixtureRowId(entry, index));
      }
    });

    it("replays offline malformed deserialization and verification with explicit EIP-2537 outcomes", async () => {
      assert.equal(MALFORMED.source_kind, "deterministic_offline_reproduction");
      const baseline = MALFORMED.baseline;
      for (const group of [1, 2]) {
        const section = `ethereum_malformed_inputs.g${group}_deserialization`;
        const rows = BLS_ROWS[section][0];
        for (const [index, entry] of rows.entries()) {
          const point = fixtureAffine(entry.encoding, group);
          // A cancelling pairing tests curve/subgroup parsing independently
          // of the signature equation. Infinity is legal to EIP-2537, while
          // compressed metadata is outside its affine-only input boundary.
          const input = group === 1
            ? ethers.concat([point, g2Bytes(noble.G2.ProjectivePoint.BASE), point, g2Bytes(noble.G2.ProjectivePoint.BASE.negate())])
            : ethers.concat([g1Bytes(noble.G1.ProjectivePoint.BASE), point, g1Bytes(noble.G1.ProjectivePoint.BASE.negate()), point]);
          const parsed = await bench.pairingCheck(input, CLEAN, REFUSAL_GAS);
          assert.equal(parsed.ok, entry.evm_affine_pairing, `${section}/${entry.label}: affine deserialization`);
          await replayVerification(bench, [group === 1 ? entry.encoding : baseline.pk], baseline.msg,
            group === 2 ? entry.encoding : baseline.signature, entry.evm_affine_verify, `${section}/${entry.label}: verify`);
          ledger.ran(section, fixtureRowId(entry, index));
        }
      }
    });

    it("replays every Ethereum standard signature and fast aggregate", async () => {
      const standard = BLS.ethereum_standard_inputs;
      for (const [index, entry] of standard.signatures.entries()) {
        await replayVerification(bench, [standard.pubkeys[entry.key]], entry.msg, entry.signature,
          true, `ethereum_standard_inputs.signatures/${index}`);
        ledger.ran("ethereum_standard_inputs.signatures", fixtureRowId(entry, index));
      }
      for (const [index, entry] of standard.fast_aggregates.entries()) {
        await replayVerification(bench, entry.keys.map((key) => standard.pubkeys[key]), entry.msg,
          entry.signature, entry.fast_aggregate_verify, `ethereum_standard_inputs.fast_aggregates/${index}`);
        ledger.ran("ethereum_standard_inputs.fast_aggregates", fixtureRowId(entry, index));
      }
    });

    it("replays the captured mainnet sync committee and dropped-participant aggregate", async () => {
      const mainnet = BLS.ethereum_mainnet_sync_committee;
      assert.equal(mainnet.dst, DST_SIG);
      // This capture provides the aggregate key, not 502 individual keys.
      // The two-pair equation is exactly the destination's verification step.
      for (const [index, entry] of BLS_ROWS.ethereum_mainnet_sync_committee[0].entries()) {
        await replayVerification(bench, [entry.aggregate_public_key.compressed], mainnet.signing_root,
          mainnet.signature, entry.fast_aggregate_verify, `ethereum_mainnet_sync_committee/${index}`,
          entry.aggregate_public_key.eip2537);
        ledger.ran("ethereum_mainnet_sync_committee", fixtureRowId(entry, index));
      }
    });

    it("replays all Rust standard verification and fast-aggregate cases", async () => {
      assert.equal(BLS_RUST.suite.dst_sig, DST_SIG);
      for (const [index, entry] of BLS_RUST.standard_vectors.verify.entries()) {
        await replayVerification(bench, [BLS_RUST.keys[entry.key].public_key], entry.message,
          entry.signature, entry.valid, `rust.standard_vectors.verify/${index}`);
        ledger.ran("rust.standard_vectors.verify", fixtureRowId(entry, index));
      }
      for (const [index, entry] of BLS_RUST.standard_vectors.fast_aggregate_verify.entries()) {
        await replayVerification(bench, entry.keys.map((key) => BLS_RUST.keys[key].public_key),
          entry.message, entry.signature, entry.valid, `rust.standard_vectors.fast_aggregate_verify/${index}`);
        ledger.ran("rust.standard_vectors.fast_aggregate_verify", fixtureRowId(entry, index));
      }
    });

    it("replays every Rust verification negative with destination-domain outcomes", async () => {
      const baseline = BLS_RUST.standard_vectors.verify.find((entry) => entry.valid && entry.key === 0);
      assert(baseline, "valid baseline for malformed public-key verification");
      for (const [index, entry] of BLS_RUST.negatives.entries()) {
        const keys = entry.public_keys ?? [entry.public_key ?? BLS_RUST.keys[entry.key].public_key];
        const message = entry.message ?? (entry.preimage ? ethers.sha256(entry.preimage) : baseline.message);
        const signature = entry.signature ?? baseline.signature;
        // A valid DST_SIG signature presented to the unrelated generic w3f
        // API fails there but succeeds on this destination. A cleared G1
        // compression flag likewise changes no affine coordinate; production
        // certificate admission checks that flag before invoking the helper.
        const expected = ["dst_sig_signature_presented_to_generic_api", "public_key_compression_flag_cleared"].includes(entry.case);
        if (entry.case === "dst_sig_signature_presented_to_generic_api") {
          assert.equal(entry.generic_valid_over_digest, false);
          assert.equal(entry.generic_valid_over_preimage, false);
        } else {
          assert.equal(entry.consensus_valid ?? entry.key_validate, false, `${entry.case}: fixture refuses`);
        }
        await replayVerification(bench, keys, message, signature, expected, `rust.negatives/${entry.case}`);
        ledger.ran("rust.negatives", fixtureRowId(entry, index));
      }
    });

    it("gives identical hash-to-G2 output on clean and on dirty memory", async () => {
      for (const trace of BLS.hash_to_g2_dst_sig) {
        const u = await bench.hashToField(trace.msg, CLEAN);
        const q = await bench.hashToG2(trace.msg, CLEAN);
        assert.equal(q, trace.q.eip2537);
        for (const fill of DIRTY) {
          assert.equal(await bench.hashToField(trace.msg, fill), u, `${trace.label}: hashToField, fill ${fill}`);
          assert.equal(await bench.hashToG2(trace.msg, fill), q, `${trace.label}: hashToG2, fill ${fill}`);
        }
      }
    });

    it("detects a build without the Z_pad writes only on dirty memory", async () => {
      const mutant = await Bench.deploy(chain, "without-z-pad");
      for (const trace of BLS.hash_to_g2_dst_sig) {
        // Fresh memory is zero, so the missing writes change nothing there.
        assert.equal(await mutant.hashToG2(trace.msg, CLEAN), trace.q.eip2537, `${trace.label}: mutant, clean memory`);
        for (const fill of FULL_FILLS) {
          const q = await mutant.hashToG2(trace.msg, fill);
          assert.equal(size(q), 256);
          assert.notEqual(q, trace.q.eip2537, `${trace.label}: mutant, fill ${fill}`);
        }
      }
    });

    it("matches an independent RFC 9380 implementation on further digests", async () => {
      const digests = [`0x${"ff".repeat(32)}`, `0x${"00".repeat(31)}01`, `0x80${"00".repeat(31)}`];
      for (let index = 0; index < 16; index += 1) {
        const preimage = ethers.concat([ethers.toUtf8Bytes("sccp/bls-harness/digest/"), ethers.toBeHex(index, 1)]);
        digests.push(ethers.sha256(preimage));
      }
      for (const digest of digests) {
        const expected = g2Bytes(noble.G2.hashToCurve(ethers.getBytes(digest), { DST: DST_SIG }));
        assert.equal(await bench.hashToG2(digest, CLEAN), expected, `hashToG2(${digest})`);
        assert.equal(await bench.hashToG2(digest, FULL_FILLS[0]), expected, `hashToG2(${digest}) on dirty memory`);
      }
    });

    it("hashes the signed message of every positive certificate to the fixture point", async () => {
      assert.equal(FINALITY.certificates.length, 13);
      for (const certificate of FINALITY.certificates) {
        assert.equal(certificate.dst, DST_SIG);
        const q = await bench.hashToG2(certificate.m, FULL_FILLS[1]);
        assert.equal(q, certificate.hash_to_g2_m.eip2537, `${certificate.label}: Q`);
      }
    });

    it("never returns a wrong point when gas runs out inside hash-to-G2", async () => {
      const trace = BLS.hash_to_g2_dst_sig[0];
      const data = bench.iface.encodeFunctionData("hashToG2", [trace.msg, ...CLEAN]);
      const outcomes = { exact: 0, emptyRevert: 0, otherFailure: 0 };
      let lowestExact = null;
      for (let gas = 25_000; gas <= 95_000; gas += 500) {
        let output = null;
        try {
          output = await chain.rpc("eth_call", [{ to: bench.address, data, gas: ethers.toQuantity(gas) }, "latest"]);
        } catch (error) {
          // A precompile that ran out of gas makes the library revert with empty
          // data; with less gas still, the frame itself runs out.
          outcomes[h.revertData(error) === "0x" ? "emptyRevert" : "otherFailure"] += 1;
          assert.equal(lowestExact, null, `a call with ${gas} gas failed after a smaller allowance succeeded`);
          continue;
        }
        assert.equal(bench.iface.decodeFunctionResult("hashToG2", output)[0], trace.q.eip2537, `gas ${gas}`);
        outcomes.exact += 1;
        lowestExact ??= gas;
      }
      assert(outcomes.exact > 0 && outcomes.emptyRevert > 0, JSON.stringify(outcomes));
      assert.equal(outcomes.exact + outcomes.emptyRevert + outcomes.otherFailure, 141);
    });

    it("adds G1 points in place and keeps the second operand", async () => {
      const keys = FINALITY.test_keys.slice(0, 4);
      const points = keys.map((key) => key.pk_eip2537);
      const curve = keys.map((key) => noble.G1.ProjectivePoint.fromHex(key.pk.slice(2)));
      keys.forEach((key, index) => {
        assert.equal(points[index], g1Bytes(curve[index]));
        assert.equal(BigInt(slice(points[index], 64, 128)), BigInt(key.pk_y));
      });
      const [ok, result] = await bench.call("g1Add", [ethers.concat([points[0], points[1]])]);
      assert.equal(ok, true);
      assert.equal(slice(result, 0, 128), g1Bytes(curve[0].add(curve[1])));
      assert.equal(slice(result, 128, 256), points[1]);

      // A + O = A, O + A = A, O + O = O: 128 zero bytes are the point at infinity.
      const identity = zeros(128);
      const withIdentity = [
        [points[2], identity, points[2]],
        [identity, points[2], points[2]],
        [identity, identity, identity],
      ];
      for (const [a, b, sum] of withIdentity) {
        const [added, pair] = await bench.call("g1Add", [ethers.concat([a, b])]);
        assert.equal(added, true);
        assert.equal(slice(pair, 0, 128), sum);
      }
      // A + (−A) = O.
      const negated = g1Bytes(curve[3].negate());
      assert.equal(BigInt(slice(negated, 64, 128)), P - BigInt(keys[3].pk_y));
      const [cancelled, cancelledPair] = await bench.call("g1Add", [ethers.concat([points[3], negated])]);
      assert.equal(cancelled, true);
      assert.equal(slice(cancelledPair, 0, 128), identity);
      assert.equal((await bench.call("g1IsInfinity", [cancelledPair]))[0], true);
    });

    it("answers false, with the buffer unchanged, when G1ADD refuses an input", async () => {
      const [a, b] = [FINALITY.test_keys[0].pk_eip2537, FINALITY.test_keys[1].pk_eip2537];
      const x = BigInt(slice(b, 0, 64));
      const y = BigInt(slice(b, 64, 128));
      const refused = {
        "y off the curve": ethers.concat([fieldElement(x), fieldElement(y + 1n)]),
        "x not below p": ethers.concat([fieldElement(x + P), fieldElement(y)]),
        "y not below p": ethers.concat([fieldElement(x), fieldElement(y + P)]),
        "non-zero padding of x": ethers.concat([fieldElement(x | (1n << 384n)), fieldElement(y)]),
        "non-zero padding of y": ethers.concat([fieldElement(x), fieldElement(y | (1n << 511n))]),
      };
      for (const [label, point] of Object.entries(refused)) {
        for (const pair of [ethers.concat([a, point]), ethers.concat([point, a])]) {
          const [ok, result, gasUsed] = await bench.call("g1Add", [pair], REFUSAL_GAS);
          assert.equal(ok, false, label);
          assert.equal(result, pair, `${label}: the buffer is unchanged`);
          assertRefusalGas(gasUsed, label);
        }
      }
      // G1ADD makes no subgroup check: a curve point outside G1 is added.
      const outside = negative("signer_key_outside_g1");
      const outsidePoints = signerPoints(outside);
      const [added] = await bench.call("g1Add", [ethers.concat(outsidePoints.slice(0, 2))]);
      assert.equal(added, true);
      // The buffer length is part of the contract of the function.
      for (const length of [0, 128, 255, 257, 384]) {
        await expectRevertData(bench.call("g1Add", [zeros(length)]), PANIC_ASSERT, `g1Add over ${length} bytes`);
      }
    });

    it("recognises the point at infinity by all four words of the first point", async () => {
      assert.equal((await bench.call("g1IsInfinity", [zeros(128)]))[0], true);
      // Only the first point is read.
      const identityThenKey = ethers.concat([zeros(128), FINALITY.test_keys[0].pk_eip2537]);
      assert.equal((await bench.call("g1IsInfinity", [identityThenKey]))[0], true);
      for (const position of [0, 31, 32, 63, 64, 95, 96, 127]) {
        const point = ethers.getBytes(zeros(128));
        point[position] = 1;
        assert.equal((await bench.call("g1IsInfinity", [point]))[0], false, `byte ${position}`);
      }
      assert.equal((await bench.call("g1IsInfinity", [FINALITY.test_keys[0].pk_eip2537]))[0], false);
      for (const length of [0, 127]) {
        const label = `g1IsInfinity over ${length} bytes`;
        await expectRevertData(bench.call("g1IsInfinity", [zeros(length)]), PANIC_ASSERT, label);
      }
    });

    it("verifies the pairing equation of every positive certificate, n = 4, 7 and 31", async () => {
      const [, , negG1] = await bench.call("constants", []);
      const sizes = new Map();
      for (const certificate of FINALITY.certificates) {
        const { label } = certificate;
        const committee = FINALITY.committees[certificate.committee];
        const points = signerPoints(certificate);
        assert.equal(points.length, committee.q, `${label}: exactly q signers`);
        assert.equal(size(certificate.evm.committee), 48 * committee.n);
        sizes.set(committee.n, (sizes.get(committee.n) ?? 0) + 1);

        // Step 7: the aggregate key, as a verifier folds the signer keys.
        const aggregate = await bench.g1Sum(points, FULL_FILLS[0]);
        assert.equal(aggregate.ok, true, `${label}: aggregation`);
        assert.equal(aggregate.infinity, false);
        assert.equal(aggregate.sum, certificate.aggregate_public_key.eip2537, `${label}: apk`);
        // Step 8: Q = hash_to_G2(m).
        const q = await bench.hashToG2(certificate.m);
        assert.equal(q, certificate.hash_to_g2_m.eip2537, `${label}: Q`);
        // §3.7: the 192-byte signature zero-extended to the 256-byte G2 input.
        const sigma = expandLimbs(certificate.evm.signature);
        assert.equal(sigma, certificate.aggregate_signature.eip2537, `${label}: σ`);
        // Step 9: e(apk, Q) · e(−g1, σ) = 1 over apk ‖ Q ‖ (−g1) ‖ σ.
        const input = ethers.concat([aggregate.sum, q, negG1, sigma]);
        assert.equal(input, certificate.pairing_input, `${label}: pairing input`);
        for (const fill of [CLEAN, FULL_FILLS[2]]) {
          const verdict = await bench.pairingCheck(input, fill);
          assert.equal(verdict.ok, true, `${label}: pairing, fill ${fill}`);
        }

        // The same points with g1 in place of −g1, and with the Q of another
        // message, are well formed and fail the equation.
        const withG1 = ethers.concat([aggregate.sum, q, FINALITY.constants.bls12_381.g1.eip2537, sigma]);
        assert.equal((await bench.pairingCheck(withG1, CLEAN, REFUSAL_GAS)).ok, false, `${label}: g1 for −g1`);
        const otherQ = await bench.hashToG2(ethers.sha256(certificate.m));
        const withOtherQ = ethers.concat([aggregate.sum, otherQ, negG1, sigma]);
        const wrongMessage = await bench.pairingCheck(withOtherQ, CLEAN, REFUSAL_GAS);
        assert.equal(wrongMessage.ok, false, `${label}: another message`);
        // A completed check costs the price of two pairs, not the forwarded gas.
        assert(wrongMessage.gasUsed < 110_000n, `${label}: a failed equation is no refusal (${wrongMessage.gasUsed})`);
      }
      assert.deepEqual([...sizes.entries()].sort((a, b) => a[0] - b[0]), [[4, 7], [7, 3], [31, 3]]);
    });

    it("accepts signer keys outside G1 whose sum is in G1, as the aggregate form of §3.8 does", async () => {
      const certificate = row(FINALITY.flavor_specific_certificates, "signer_keys_outside_g1_cancelling");
      assert.equal(certificate.expected.evm, "ok");
      const [, , negG1] = await bench.call("constants", []);
      const aggregate = await bench.g1Sum(signerPoints(certificate));
      assert.equal(aggregate.ok, true);
      const q = await bench.hashToG2(certificate.m);
      const input = ethers.concat([aggregate.sum, q, negG1, expandLimbs(certificate.evm.signature)]);
      assert.equal((await bench.pairingCheck(input)).ok, true);
    });

    it("answers false when a signer point makes G1ADD refuse, and reads (0, 0) as the identity", async () => {
      for (const label of ["signer_y_off_curve", "signer_x_ge_p", "signer_y_ge_p"]) {
        const certificate = negative(label);
        assert.equal(certificate.expected.evm, "BadCommittee");
        const aggregate = await bench.g1Sum(signerPoints(certificate), CLEAN, REFUSAL_GAS);
        assert.equal(aggregate.ok, false, label);
        assertRefusalGas(aggregate.gasUsed, label);
      }
      // (0, 0) is the point at infinity to G1ADD, so the signer silently leaves
      // the aggregate: the caller must refuse these coordinates itself (§5.2.4).
      const dropped = negative("signer_zero_coordinates");
      const droppedPoints = signerPoints(dropped);
      assert.equal(droppedPoints[0], zeros(128));
      const withZero = await bench.g1Sum(droppedPoints);
      const withoutIt = await bench.g1Sum(droppedPoints.slice(1));
      assert.equal(withZero.ok, true);
      assert.equal(withZero.infinity, false);
      assert.equal(withZero.sum, withoutIt.sum);
      // Three keys that sum to the identity: the additions succeed and the sum is O.
      for (const label of ["aggregate_key_identity", "aggregate_key_identity_sigma_off_curve"]) {
        const aggregate = await bench.g1Sum(signerPoints(negative(label)));
        assert.equal(aggregate.ok, true, label);
        assert.equal(aggregate.infinity, true, label);
        assert.equal(aggregate.sum, zeros(128), label);
      }
      // One point alone is returned as it is.
      const single = await bench.g1Sum([FINALITY.test_keys[5].pk_eip2537]);
      assert.deepEqual([single.ok, single.infinity, single.sum], [true, false, FINALITY.test_keys[5].pk_eip2537]);
    });

    it("answers false when PAIRING_CHECK refuses an input, and never true", async () => {
      const [, , negG1] = await bench.call("constants", []);
      // Rows whose signed message is the one a verifier derives, with a σ or an
      // aggregate key that the precompile refuses.
      const refused = [
        "sigma_not_in_subgroup",
        "sigma_off_curve",
        "sigma_c0_c1_swapped",
        "sigma_limb_x_c0_ge_p",
        "sigma_limb_x_c1_ge_p",
        "sigma_limb_y_c0_ge_p",
        "sigma_limb_y_c1_ge_p",
        "signer_key_outside_g1",
      ];
      for (const label of refused) {
        const certificate = negative(label);
        assert.equal(certificate.expected.evm, "BadSignature", label);
        assert("forgery_evidence_id" in certificate, `${label}: m is the verifier's message`);
        const aggregate = await bench.g1Sum(signerPoints(certificate));
        assert.equal(aggregate.ok, true, `${label}: the signer points are on the curve`);
        assert.equal(aggregate.infinity, false, label);
        const q = await bench.hashToG2(certificate.m);
        const input = ethers.concat([aggregate.sum, q, negG1, expandLimbs(certificate.evm.signature)]);
        const verdict = await bench.pairingCheck(input, CLEAN, REFUSAL_GAS);
        assert.equal(verdict.ok, false, label);
        assertRefusalGas(verdict.gasUsed, label);
      }

      // A Q that is not a point is refused as well.
      const certificate = positive("n4_lowest_q");
      const input = ethers.getBytes(certificate.pairing_input);
      const brokenQ = Uint8Array.from(input);
      brokenQ[128 + 255] ^= 1;
      const brokenVerdict = await bench.pairingCheck(brokenQ, CLEAN, REFUSAL_GAS);
      assert.equal(brokenVerdict.ok, false);
      assertRefusalGas(brokenVerdict.gasUsed, "Q off the curve");

      // The input length is part of the contract of the function.
      for (const length of [0, 384, 767, 769, 1152]) {
        const data = ethers.concat([certificate.pairing_input, certificate.pairing_input]).slice(0, 2 + 2 * length);
        await expectRevertData(bench.pairingCheck(data), PANIC_ASSERT, `pairingCheck over ${length} bytes`);
      }
    });

    it("rejects a quorum signature made under another hash domain", async () => {
      // The n = 4 committee signs the commit digest under the w3f transcript:
      // σ is a point of G2 and the keys are genuine, but Q is hashed under
      // DST_SIG, so the check completes and the equation fails (§3.8, §9.5).
      const [, , negG1] = await bench.call("constants", []);
      const certificate = row(FINALITY_RUST.negative_certificates, "w3f_transcript_over_commit_digest");
      assert.equal(certificate.expected.evm, "BadSignature");
      assert("forgery_evidence_id" in certificate, "m is the verifier's message");
      const aggregate = await bench.g1Sum(signerPoints(certificate));
      assert.deepEqual([aggregate.ok, aggregate.infinity], [true, false]);
      assert.equal(aggregate.sum, positive("n4_lowest_q").aggregate_public_key.eip2537);
      const q = await bench.hashToG2(certificate.m);
      const input = ethers.concat([aggregate.sum, q, negG1, expandLimbs(certificate.evm.signature)]);
      const verdict = await bench.pairingCheck(input, CLEAN, REFUSAL_GAS);
      assert.equal(verdict.ok, false);
      assert(verdict.gasUsed < 110_000n, `the equation fails without a refusal (${verdict.gasUsed})`);
    });

    it("shows why the caller must refuse σ = O and apk = O itself", async () => {
      const [, , negG1] = await bench.call("constants", []);
      const certificate = positive("n4_lowest_q");
      const apk = certificate.aggregate_public_key.eip2537;
      const q = certificate.hash_to_g2_m.eip2537;
      const sigma = certificate.aggregate_signature.eip2537;
      // The identity signature of the fixture: e(apk, Q) · e(−g1, O) = e(apk, Q) ≠ 1.
      assert.equal(expandLimbs(negative("sigma_zero").evm.signature), zeros(256));
      const identitySigma = ethers.concat([apk, q, negG1, zeros(256)]);
      assert.equal((await bench.pairingCheck(identitySigma, CLEAN, REFUSAL_GAS)).ok, false);
      // An identity aggregate key with a genuine σ: e(O, Q) · e(−g1, σ) ≠ 1.
      const identityKey = ethers.concat([zeros(128), q, negG1, sigma]);
      assert.equal((await bench.pairingCheck(identityKey, CLEAN, REFUSAL_GAS)).ok, false);
      // Both identities satisfy the equation for every message: the precompile
      // accepts the point at infinity, so the library answers true.
      assert.equal((await bench.pairingCheck(ethers.concat([zeros(128), q, negG1, zeros(256)]))).ok, true);
      assert.equal((await bench.pairingCheck(zeros(768))).ok, true);
    });

    it("refuses a precompile answer of the wrong length, as on a chain without the precompile", async () => {
      const emptyAccount = ethers.zeroPadValue(EMPTY_ACCOUNT, 20);
      assert.equal(await chain.rpc("eth_getCode", [emptyAccount, "latest"]), "0x");
      assert.equal(await chain.rpc("eth_call", [{ to: emptyAccount, data: "0x01" }, "latest"]), "0x");
      const trace = BLS.hash_to_g2_dst_sig[0];
      const elements = ethers.concat([trace.map_fp2_to_g2_input_u0, trace.map_fp2_to_g2_input_u1]);
      const certificate = positive("n4_lowest_q");
      const one = ethers.toBeHex(1, 32);

      // No EIP-2537: SHA-256 and MODEXP answer, so the field elements are right,
      // and the first mapping call, which succeeds with no data, stops the hash.
      const noBls = await Bench.deploy(chain, "without-eip-2537");
      assert.equal(await noBls.hashToField(trace.msg), elements);
      for (const fill of [CLEAN, FULL_FILLS[0]]) {
        const label = `hashToG2 without EIP-2537, fill ${fill}`;
        await expectRevertData(noBls.call("hashToG2", [trace.msg, ...fill]), "0x", label);
      }
      // G1ADD: false, the buffer as it was, and no gas lost to a refusal.
      const pair = ethers.concat([FINALITY.test_keys[0].pk_eip2537, FINALITY.test_keys[1].pk_eip2537]);
      const [added, result, addGas] = await noBls.call("g1Add", [pair], REFUSAL_GAS);
      assert.deepEqual([added, result], [false, pair]);
      assert(addGas < 10_000n, `an answer of the wrong length is not a refusal (${addGas})`);
      assert.equal((await noBls.g1Sum(signerPoints(certificate))).ok, false);
      // PAIRING_CHECK: false for a genuine certificate, also when the scratch
      // word that would receive the result already holds the value 1.
      for (const fill of [CLEAN, [1, one], [64, one]]) {
        const verdict = await noBls.pairingCheck(certificate.pairing_input, fill, REFUSAL_GAS);
        assert.equal(verdict.ok, false, `pairingCheck without EIP-2537, fill ${fill}`);
        assert(verdict.gasUsed < 10_000n);
      }
      // The same input and fills verify where the precompile exists.
      for (const fill of [CLEAN, [1, one], [64, one]]) {
        assert.equal((await bench.pairingCheck(certificate.pairing_input, fill)).ok, true);
      }

      // Each remaining call site: the last call of hash-to-G2, the field
      // reductions and the hash blocks.
      const noG2Add = await Bench.deploy(chain, "without-g2add");
      assert.equal(await noG2Add.hashToField(trace.msg), elements);
      await expectRevertData(noG2Add.call("hashToG2", [trace.msg, ...FULL_FILLS[0]]), "0x", "hashToG2 without G2ADD");
      for (const kind of ["without-modexp", "without-sha256"]) {
        const variant = await Bench.deploy(chain, kind);
        for (const name of ["hashToField", "hashToG2"]) {
          await expectRevertData(variant.call(name, [trace.msg, ...FULL_FILLS[0]]), "0x", `${name} ${kind}`);
        }
      }
    });

    it("records the gas of hash-to-G2, the pairing check and G1 aggregation", async (t) => {
      const trace = BLS.hash_to_g2_dst_sig[0];
      const [, hashToField] = await bench.call("hashToField", [trace.msg, ...CLEAN]);
      const [, hashToG2] = await bench.call("hashToG2", [trace.msg, ...CLEAN]);
      const gas = { hashToField, hashToG2 };
      // Neither depends on the digest.
      for (const other of BLS.hash_to_g2_dst_sig.slice(1)) {
        assert.equal((await bench.call("hashToG2", [other.msg, ...CLEAN]))[1], hashToG2);
      }
      // The pairing check costs the same for every committee size: the input
      // is always two pairs.
      for (const label of ["n4_lowest_q", "n7_scattered_q", "n31_scattered_q"]) {
        const verdict = await bench.pairingCheck(positive(label).pairing_input);
        assert.equal(verdict.ok, true);
        gas.pairingCheck ??= verdict.gasUsed;
        assert.equal(verdict.gasUsed, gas.pairingCheck, label);
      }
      // One addition, and the harness fold of q signer keys (q − 1 additions,
      // each with the 128-byte calldata copy of the harness loop).
      const pair = ethers.concat([FINALITY.test_keys[0].pk_eip2537, FINALITY.test_keys[1].pk_eip2537]);
      [, , gas.g1Add] = await bench.call("g1Add", [pair]);
      for (const label of ["n4_lowest_q", "n7_scattered_q", "n31_scattered_q"]) {
        const points = signerPoints(positive(label));
        gas[`g1Sum of ${points.length} signers`] = (await bench.g1Sum(points)).gasUsed;
      }
      for (const [label, value] of Object.entries(gas)) t.diagnostic(`${hardfork} gas ${label}: ${value}`);
      for (const [label, recorded] of Object.entries(RECORDED_GAS[hardfork])) {
        const withinBound = 10n * gas[label] <= 11n * recorded;
        assert(withinBound, `${hardfork} ${label}: ${gas[label]} gas is above 1.1 × ${recorded}`);
      }
      measured[hardfork] = gas;
    });

    it("accounts for every BLS verification row and lists every out-of-scope API", (t) => {
      const counts = {};
      for (const [group, [rows, minimum]] of Object.entries(BLS_ROWS)) {
        assert(rows.length >= minimum, `${group}: fixture shrank below ${minimum} rows`);
        assert.deepEqual(ledger.rows(group), rows.map(fixtureRowId).sort(), `${group}: every fixture row ran`);
        counts[group] = rows.length;
      }
      assert.deepEqual(ledger.counts(), counts, "only executed fixture groups are counted");
      t.diagnostic(`${hardfork} BLS executed rows: ${JSON.stringify(counts)}; total ${Object.values(counts).reduce((a, b) => a + b, 0)}`);
      for (const [group, [rows, minimum, reason]] of Object.entries(BLS_SKIPS)) {
        assert(rows.length >= minimum, `${group}: skipped fixture group shrank below ${minimum} rows`);
        t.diagnostic(`${hardfork} BLS outside contract API: ${group}, ${rows.length} rows; ${reason}`);
      }
    });
  });
}

describe("BLS12_381 gas across hardforks", () => {
  it("differs between Prague and Osaka by the MODEXP repricing of hash-to-G2 only", () => {
    const { prague, osaka } = measured;
    assert(prague && osaka, "both hardforks were measured");
    assert.equal(osaka.hashToField - prague.hashToField, MODEXP_REPRICING);
    assert.equal(osaka.hashToG2 - prague.hashToG2, MODEXP_REPRICING);
    assert.equal(osaka.pairingCheck, prague.pairingCheck);
    assert.equal(osaka.g1Add, prague.g1Add);
  });
});
