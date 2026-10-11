"use strict";

// EDR harness for `SccpTairaXor.sol` (`specs/sccp.md` §5.2, §11.4 item 3):
// authenticated artifact loading through `scripts/contract_artifact_corridor.py`,
// isolated chains per destination profile and hardfork on the locked native EDR
// runtime, deployment through the deterministic deployer of §5.2.1 at its
// CREATE2 address, explicit block-time control, strict custom-error decoding,
// the destination state in the shape of the shared fixtures, and gas capture.
// Calls are encoded and results decoded with the interface of the independent
// model (`sccp_v1_model.js`), never with the ABI the compiler emitted.
//
// Requires Python 3 and the locked `scripts/contract_tooling/evm-runtime`
// dependencies. Developer conveniences, for tests only:
// `SCCP_CONTRACT_ARTIFACT_MANIFEST` names an already built manifest,
// `SCCP_CONTRACT_ARTIFACT_LOCK` an artifact lock other than the committed one
// (a contract change whose lock is not regenerated yet), and
// `SCCP_CORRIDOR_PYTHON_BIN` the Python that runs the corridor.

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const model = require("./sccp_v1_model.js");

const { ethers, REPO, RUNTIME_DIR } = model;
const { createNativeEdrProvider } = require(path.join(RUNTIME_DIR, "edr-provider.js"));

const CONTRACT = "contracts/evm/sccp/SccpTairaXor.sol:SccpTairaXor";
const CORRIDOR = path.join(REPO, "scripts", "contract_artifact_corridor.py");
const DEFAULT_MANIFEST = path.join(REPO, "target", "sccp-contract-artifacts", "sccp-contract-artifacts-v1.json");
const COMMITTED_ARTIFACT_LOCK = path.join(REPO, "scripts", "contract_tooling", "artifact-lock.json");
const BLOCK_GAS_LIMIT = 60_000_000;
// Below the EIP-7825 transaction gas cap of 2^24 that Osaka applies.
const TX_GAS_LIMIT = 16_000_000n;
// §5.2.3: the non-mapping storage slots (A, B, C and `totalSupply`) lie in 0..8.
const STORAGE_SLOTS = 9;
const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);

function pythonBin() {
  return process.env.SCCP_CORRIDOR_PYTHON_BIN || "python3";
}

function artifactLockPath() {
  const explicit = process.env.SCCP_CONTRACT_ARTIFACT_LOCK;
  return explicit ? path.resolve(explicit) : COMMITTED_ARTIFACT_LOCK;
}

function runCorridor(args) {
  return spawnSync(pythonBin(), [CORRIDOR, ...args], { cwd: REPO, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
}

function requireCorridor(args) {
  const result = runCorridor(args);
  const reason = result.stderr || result.error?.message;
  assert.equal(result.status, 0, `contract artifact corridor ${args[0]} failed: ${reason}`);
}

let cachedArtifacts = null;

/**
 * Loads the SccpTairaXor artifact from a manifest that the corridor has just
 * re-verified against the compiler lock, the artifact lock and this checkout.
 * The default manifest is (re)built when it is missing or stale.
 */
function loadArtifacts() {
  if (cachedArtifacts) return cachedArtifacts;
  const explicit = process.env.SCCP_CONTRACT_ARTIFACT_MANIFEST;
  const manifestPath = explicit ? path.resolve(explicit) : DEFAULT_MANIFEST;
  const lockPath = artifactLockPath();
  const verify = ["verify", "--manifest", manifestPath, "--artifact-lock", lockPath];
  if (explicit) {
    requireCorridor(verify);
  } else if (!fs.existsSync(manifestPath) || runCorridor(verify).status !== 0) {
    requireCorridor(["build", "--artifact-lock", lockPath]);
    requireCorridor(verify);
  }
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  const found = manifest.targets.evm.contracts.filter((entry) => entry.fully_qualified_name === CONTRACT);
  assert.equal(found.length, 1, `the manifest must contain exactly one ${CONTRACT}`);
  const [evm] = found;
  cachedArtifacts = Object.freeze({
    manifestPath,
    evm,
    lock: JSON.parse(fs.readFileSync(lockPath, "utf8")),
    abi: evm.abi,
    // The compiler's ABI, for comparison with the model's interface only.
    iface: new ethers.Interface(evm.abi),
    creation: evm.creation_bytecode.hex,
    runtimeTemplate: evm.runtime_bytecode.hex,
    immutableReferences: evm.runtime_immutable_references,
  });
  return cachedArtifacts;
}

/** Revert data of a failed EDR request, or null when the failure is not a plain revert. */
function revertData(error) {
  for (const candidate of [error, error?.error, error?.cause]) {
    const data = candidate?.data;
    if (data && typeof data === "object" && typeof data.data === "string" && data.reason
        && Object.keys(data.reason).length === 1 && data.reason.Revert === data.data) {
      return data.data;
    }
  }
  return null;
}

/**
 * Decodes revert data with `contractInterface`: `{name: null}` for empty data,
 * else `{name, args}` of the custom error. Data that is no declared error fails.
 */
function decodeRevert(data, contractInterface = model.iface) {
  if (data === "0x") return { name: null, args: [] };
  const parsed = contractInterface.parseError(data);
  assert(parsed, `revert data is no declared error: ${data}`);
  return { name: parsed.name, args: [...parsed.args] };
}

/** Human-readable form of revert data, for failure messages. */
function describeRevert(data) {
  if (data === "0x") return "empty revert data";
  const parsed = model.iface.parseError(data);
  return parsed ? `${parsed.name}(${[...parsed.args].join(", ")})` : `undeclared revert data ${data}`;
}

/**
 * Awaits `promise` and requires a revert with exactly the named custom error
 * (and arguments); `name === null` requires empty revert data.
 */
async function expectRevert(promise, name, args) {
  let failure = null;
  try {
    await promise;
  } catch (error) {
    failure = error;
  }
  assert(failure, `expected revert ${name}, but the call succeeded`);
  const data = revertData(failure);
  assert(data !== null, `expected revert ${name}, got ${failure.message}`);
  const decoded = decodeRevert(data);
  assert.equal(decoded.name, name, `expected revert ${name}, got ${describeRevert(data)}`);
  if (args !== undefined) {
    assert.deepEqual(decoded.args.map((value) => (typeof value === "bigint" ? value : String(value))), args);
  }
}

/**
 * One isolated EDR chain with explicit block timestamps. `hardfork` is
 * "prague" or "osaka" and has no default: every suite states the execution
 * rules it runs under (`scripts/contract_tooling/evm-runtime/edr-provider.js`).
 * Block time strictly increases unless `allowBlocksWithSameTimestamp` is set,
 * which fixture replays need: their steps may share one block time.
 */
class Chain {
  static async open(profile, { hardfork, allowBlocksWithSameTimestamp = false } = {}) {
    const provider = createNativeEdrProvider({
      chainId: Number(profile.chainId),
      blockGasLimit: BLOCK_GAS_LIMIT,
      hardfork,
      allowBlocksWithSameTimestamp,
    });
    const chain = new Chain(profile, provider, hardfork, allowBlocksWithSameTimestamp);
    chain.accounts = await provider.request({ method: "eth_accounts" });
    chain.time = (await chain.latest()).timestamp;
    return chain;
  }

  constructor(profile, provider, hardfork, sameTimestamp) {
    this.profile = profile;
    this.provider = provider;
    this.hardfork = hardfork;
    this.sameTimestamp = sameTimestamp;
    this.accounts = [];
    this.time = 0n;
  }

  rpc(method, params = []) {
    return this.provider.request({ method, params });
  }

  /** Number and timestamp (seconds) of the latest block. */
  async latest() {
    const block = await this.rpc("eth_getBlockByNumber", ["latest", false]);
    return { number: BigInt(block.number), timestamp: BigInt(block.timestamp) };
  }

  /** Timestamp (seconds) of the latest block, in milliseconds: the destination clock `now_ms`. */
  nowMs() {
    return this.time * 1000n;
  }

  /**
   * Fixes the timestamp of the next block to `at` seconds (default: one second
   * after the latest block) and returns it. Block time never decreases, and it
   * repeats only on a chain opened with `allowBlocksWithSameTimestamp`.
   */
  async setNextTimestamp(at) {
    const timestamp = at === undefined ? this.time + 1n : BigInt(at);
    assert(
      this.sameTimestamp ? timestamp >= this.time : timestamp > this.time,
      `block timestamps must ${this.sameTimestamp ? "not decrease" : "increase"} (${timestamp} after ${this.time})`,
    );
    await this.rpc("evm_setNextBlockTimestamp", [ethers.toQuantity(timestamp)]);
    this.time = timestamp;
    return timestamp;
  }

  /**
   * Sends one transaction in a block at `at` seconds (default: one second
   * after the latest block). Returns `{receipt}`, or `{revert, error}` with the
   * revert data when the transaction reverted; the reverted transaction is
   * mined too, so the chain's clock is at `at` in both cases.
   */
  async attempt({ from = 0, to, data, at, value, gas = TX_GAS_LIMIT }) {
    const timestamp = await this.setNextTimestamp(at);
    const tx = { from: typeof from === "number" ? this.accounts[from] : from, data, gas: ethers.toQuantity(gas) };
    if (to !== undefined) tx.to = to;
    if (value !== undefined) tx.value = ethers.toQuantity(value);
    let hash;
    try {
      hash = await this.rpc("eth_sendTransaction", [tx]);
    } catch (error) {
      const revert = revertData(error);
      if (revert === null) throw error;
      if ((await this.latest()).timestamp !== timestamp) await this.rpc("evm_mine");
      const head = await this.latest();
      assert.equal(head.timestamp, timestamp, "a reverted transaction leaves the clock at its block time");
      return { revert, error };
    }
    const receipt = await this.rpc("eth_getTransactionReceipt", [hash]);
    assert.equal(receipt.status, "0x1", "mined transaction must succeed");
    return { receipt };
  }

  /** Like `attempt`, but a revert is thrown as the EDR error; returns the receipt. */
  async send(request) {
    const outcome = await this.attempt(request);
    if (outcome.error) throw outcome.error;
    return outcome.receipt;
  }

  /** Mines one empty block at `at` seconds (default: one second after the latest block). */
  async mine(at) {
    await this.setNextTimestamp(at);
    await this.rpc("evm_mine");
  }

  /** Read-only call against the latest block (its timestamp and state). */
  call(to, data, from) {
    const request = { to, data, gas: ethers.toQuantity(TX_GAS_LIMIT) };
    if (from !== undefined) request.from = typeof from === "number" ? this.accounts[from] : from;
    return this.rpc("eth_call", [request, "latest"]);
  }

  /** The return data of a mined transaction, read from its execution trace. */
  async returnData(receipt) {
    const trace = await this.rpc("debug_traceTransaction", [
      receipt.transactionHash,
      { disableStorage: true, disableMemory: true, disableStack: true },
    ]);
    assert.equal(trace.failed, false, "the traced transaction succeeded");
    return trace.returnValue.startsWith("0x") ? trace.returnValue : `0x${trace.returnValue}`;
  }

  /** Takes a snapshot of the chain and returns its id; `restore` returns to it once. */
  snapshot() {
    return this.rpc("evm_snapshot");
  }

  /** Returns the chain, its state and its clock, to `snapshot`, which is consumed. */
  async restore(snapshot) {
    assert.equal(await this.rpc("evm_revert", [snapshot]), true, "the snapshot exists");
    this.time = (await this.latest()).timestamp;
  }

  /**
   * Puts the runtime of the deterministic-deployment proxy at
   * `SCCP_EVM_DEPLOYER` (§5.2.1), where a real chain already has it.
   */
  async installDeployer() {
    const installed = await this.rpc("eth_getCode", [model.SCCP_EVM_DEPLOYER, "latest"]);
    if (installed === model.SCCP_EVM_DEPLOYER_RUNTIME) return;
    assert.equal(installed, "0x", "nothing else occupies the deployer address");
    await this.rpc("hardhat_setCode", [model.SCCP_EVM_DEPLOYER, model.SCCP_EVM_DEPLOYER_RUNTIME]);
  }

  close() {
    return this.provider.disconnect();
  }
}

/** A JSON integer as the fixtures write it: a number below 2^53, else its decimal string. */
function jsonInteger(value) {
  const number = BigInt(value);
  return number <= MAX_SAFE ? Number(number) : number.toString();
}

/** A deployed SccpTairaXor (or a contract that inherits it) with ABI helpers. */
class Destination {
  constructor(chain, address, contractInterface = model.iface) {
    this.chain = chain;
    this.address = ethers.getAddress(address);
    this.iface = contractInterface;
  }

  /** Calls view `name` against the latest block and returns its decoded result. */
  async view(name, args = []) {
    const output = await this.chain.call(this.address, this.iface.encodeFunctionData(name, args));
    const decoded = this.iface.decodeFunctionResult(name, output);
    return decoded.length === 1 ? decoded[0] : decoded;
  }

  /** Simulates `name` against the latest block and returns its decoded result. */
  async simulate(name, args, from = 0) {
    const output = await this.chain.call(this.address, this.iface.encodeFunctionData(name, args), from);
    const decoded = this.iface.decodeFunctionResult(name, output);
    return decoded.length === 1 ? decoded[0] : decoded;
  }

  tx(name, args, options = {}) {
    return this.chain.send({ ...options, to: this.address, data: this.iface.encodeFunctionData(name, args) });
  }

  raw(data, options = {}) {
    return this.chain.send({ ...options, to: this.address, data });
  }

  /** Sends raw calldata; returns `{receipt}` or `{revert, error}` (`Chain.attempt`). */
  attempt(data, options = {}) {
    return this.chain.attempt({ ...options, to: this.address, data });
  }

  /** The raw logs `{topics, data}` of `receipt`, every one of which this contract must have emitted. */
  logs(receipt) {
    return receipt.logs.map((log) => {
      assert.equal(ethers.getAddress(log.address), this.address, "every log comes from the destination");
      return { topics: [...log.topics], data: log.data };
    });
  }

  /** Logs of this contract in `receipt`, parsed with the model interface. */
  events(receipt, name) {
    return this.logs(receipt)
      .map((log) => ({ log, parsed: this.iface.parseLog(log) }))
      .filter((entry) => entry.parsed && (name === undefined || entry.parsed.name === name));
  }

  /**
   * The destination state in the `state_after` shape of the shared fixtures
   * (`committee_transitions_v1.json`), read through views only at the latest
   * block. Checkpoints and consumed nonces live in mappings, so the caller
   * names the `heights` and `nonces` to probe; the result lists those that are
   * set, in ascending order.
   */
  async state({ heights = [], nonces = [] } = {}) {
    const committee = await this.view("committeeState");
    const pause = await this.view("pauseState");
    const equivocated = await this.view("equivocated");
    const nowMs = (await this.chain.latest()).timestamp * 1000n;
    assert.equal(await this.view("controlNonce"), pause[2], "controlNonce() and pauseState() agree");
    assert.equal(await this.view("mintingPaused"), pause[3], "mintingPaused() and pauseState() agree");
    const ascending = (values) =>
      [...new Set(values.map((value) => BigInt(value)))].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    const checkpoints = [];
    for (const height of ascending(heights)) {
      const id = await this.view("checkpointHeader", [height]);
      if (id !== model.ZERO32) checkpoints.push({ height: jsonInteger(height), id });
    }
    const consumed = [];
    for (const nonce of ascending(nonces)) {
      if (await this.view("isConsumed", [nonce])) consumed.push(jsonInteger(nonce));
    }
    return {
      checkpoints,
      committee: {
        generation: jsonInteger(committee[4]),
        high: jsonInteger(committee[3]),
        root: committee[0],
        start: jsonInteger(committee[2]),
        until_ms: jsonInteger(committee[1]),
      },
      consumed,
      equivocated,
      live: !equivocated && nowMs <= committee[1],
      op_count: jsonInteger(await this.view("opCount")),
      pause: {
        control_nonce: jsonInteger(pause[2]),
        effective: pause[3],
        fast_pause_until_ms: jsonInteger(pause[1]),
        parliament_paused: pause[0],
      },
      total_supply: (await this.view("totalSupply")).toString(),
    };
  }
}

/**
 * The constructor fields of the model for a fixture `deployment`
 * (`{taira_network_id, consensus_instance, network, route_revision,
 * max_wrapped_supply, pin}`), on `profile` (default: the fixture's network).
 */
function deploymentOf(fixture, profile = model.profileOf(fixture.network)) {
  return {
    tairaNetworkId: fixture.taira_network_id,
    consensusInstance: fixture.consensus_instance,
    networkTag: profile.tag,
    routeRevision: fixture.route_revision,
    maxWrappedSupply: BigInt(fixture.max_wrapped_supply),
    initialGeneration: BigInt(fixture.pin.generation),
    initialCommitteeRoot: fixture.pin.committee_root,
    initialStartHeight: BigInt(fixture.pin.start_height),
    initialUntilMs: BigInt(fixture.pin.until_ms),
  };
}

/** The init code `creation code ‖ abi.encode(constructor arguments)` of a deployment. */
function initCode(deployment, creation = loadArtifacts().creation) {
  return ethers.concat([creation, model.encodeConstructorArgs(deployment)]);
}

/**
 * Deploys through `SCCP_EVM_DEPLOYER` with salt `0^32` (§5.2.1), the only
 * path that creates a destination, and returns the `Destination` at the
 * CREATE2 address the model computes from the init code. `creation` and
 * `contractInterface` select a contract that inherits SccpTairaXor instead of
 * the locked build.
 */
async function deploy(chain, deployment, { at, from = 0, creation, contractInterface } = {}) {
  await chain.installDeployer();
  const init = initCode(deployment, creation);
  const address = model.create2Address(init);
  assert.equal(await chain.rpc("eth_getCode", [address, "latest"]), "0x", "the CREATE2 address is unused");
  const data = ethers.concat([model.SCCP_EVM_SALT, init]);
  const receipt = await chain.send({ from, to: model.SCCP_EVM_DEPLOYER, data, at });
  const code = await chain.rpc("eth_getCode", [address, "latest"]);
  assert.notEqual(code, "0x", "the deployer created the contract at its CREATE2 address");
  return { destination: new Destination(chain, address, contractInterface), receipt, address, init };
}

/**
 * Runs the init code of `deployment` in a plain creation transaction. The
 * deployer answers a failed creation with empty revert data, so this is how a
 * test reads the constructor's own error; destinations come from `deploy`.
 * Returns `{receipt}` or `{revert, error}`.
 */
function createDirectly(chain, deployment, { at, from = 0, creation } = {}) {
  return chain.attempt({ from, data: initCode(deployment, creation), at });
}

/**
 * Copies the runtime code and the non-mapping storage of a freshly deployed
 * `destination` to `address` and returns the copy. The shared fixtures bind
 * leaves to the destination word `word(0x22…22)`, which no CREATE2 address
 * equals; the contract derives its destination word from `address()` at run
 * time, so the copy at that address is the destination the fixtures describe.
 */
async function relocate(destination, address) {
  const { chain } = destination;
  const target = ethers.getAddress(address);
  await chain.rpc("hardhat_setCode", [target, await chain.rpc("eth_getCode", [destination.address, "latest"])]);
  for (let slot = 0; slot < STORAGE_SLOTS; slot += 1) {
    const key = ethers.toQuantity(slot);
    const value = await chain.rpc("eth_getStorageAt", [destination.address, key, "latest"]);
    await chain.rpc("hardhat_setStorageAt", [target, key, value]);
  }
  const copy = new Destination(chain, target, destination.iface);
  for (const view of ["committeeState", "initialCommittee", "pauseState", "opCount", "totalSupply", "equivocated"]) {
    const original = await destination.view(view);
    const relocated = await copy.view(view);
    assert.deepEqual(
      typeof relocated === "object" ? [...relocated] : relocated,
      typeof original === "object" ? [...original] : original,
      `the relocated destination keeps ${view}()`,
    );
  }
  return copy;
}

/**
 * Deploys a minimal forwarder whose runtime relays its calldata to `target`
 * with CALL and bubbles the result, so `msg.sender != tx.origin` at the target.
 */
async function deployForwarder(chain, target) {
  const runtime = ethers.concat([
    "0x365f5f375f5f365f5f73",
    target,
    "0x5af13d5f5f3e602a573d5ffd5b3d5ff3",
  ]);
  assert.equal(ethers.getBytes(runtime).length, 46, "forwarder runtime layout");
  const init = ethers.concat(["0x602e8060095f395ff3", runtime]);
  const receipt = await chain.send({ data: init });
  return ethers.getAddress(receipt.contractAddress);
}

/** Runtime bytecode the corridor template yields once the named immutables are filled. */
function expectedRuntime(values) {
  const { runtimeTemplate, immutableReferences } = loadArtifacts();
  const bytes = ethers.getBytes(runtimeTemplate);
  for (const reference of immutableReferences) {
    assert(Object.hasOwn(values, reference.name), `missing immutable ${reference.name}`);
    bytes.set(ethers.getBytes(values[reference.name]), reference.start);
  }
  return ethers.hexlify(bytes);
}

/** The nine §5.2.3 immutables of a deployment as the 32-byte words the runtime code holds. */
function immutableWords(deployment) {
  return {
    TAIRA_NETWORK_ID: deployment.tairaNetworkId,
    CONSENSUS_INSTANCE: deployment.consensusInstance,
    NETWORK_TAG: model.word(deployment.networkTag),
    ROUTE_REVISION: model.word(deployment.routeRevision),
    MAX_WRAPPED_SUPPLY: model.word(deployment.maxWrappedSupply),
    INITIAL_GENERATION: model.word(deployment.initialGeneration),
    INITIAL_COMMITTEE_ROOT: deployment.initialCommitteeRoot,
    INITIAL_START_HEIGHT: model.word(deployment.initialStartHeight),
    INITIAL_UNTIL_MS: model.word(deployment.initialUntilMs),
  };
}

/**
 * Compiles test-only Solidity sources with the pinned native compiler and the
 * locked settings through `scripts/contract_native_solc.js`, outside the
 * artifact lock. `sourcePaths` are repository-relative and name every source
 * the compilation needs; `overrides` maps a path to content that replaces the
 * checkout's (mutation tests). Any compiler diagnostic, a warning included,
 * fails. Returns the standard-json `contracts` output.
 */
function compileTestSources(sourcePaths, overrides = {}) {
  const { compileNativeSolidity } = require(path.join(REPO, "scripts", "contract_native_solc.js"));
  const lockPath = path.join(REPO, "scripts", "contract_tooling", "compiler-lock.json");
  const lock = JSON.parse(fs.readFileSync(lockPath, "utf8"));
  const sources = {};
  for (const sourcePath of sourcePaths) {
    const content = Object.hasOwn(overrides, sourcePath)
      ? overrides[sourcePath]
      : fs.readFileSync(path.join(REPO, sourcePath), "utf8");
    sources[sourcePath] = { content };
  }
  for (const sourcePath of Object.keys(overrides)) {
    assert(Object.hasOwn(sources, sourcePath), `override of a source that is not compiled: ${sourcePath}`);
  }
  const input = JSON.stringify({ language: "Solidity", sources, settings: lock.settings });
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "sccp-test-solc-"));
  try {
    const compilerPath = path.join(directory, "evm-solc");
    requireCorridor(["materialize", "--target", "evm", "--output", compilerPath]);
    const output = compileNativeSolidity(input, { target: "evm", compilerPath, pythonBin: pythonBin() });
    const diagnostics = (output.errors ?? []).map((entry) => entry.formattedMessage ?? entry.message);
    assert.deepEqual(diagnostics, [], "test-only sources must compile without any diagnostic");
    return output.contracts;
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

/**
 * Calldata size and the gas it costs before execution: `intrinsic` is `21000 +
 * 4·zero + 16·nonzero` and `floor` the EIP-7623 minimum `21000 + 10·(zero +
 * 4·nonzero)` of a transaction with this calldata.
 */
function calldataCost(data) {
  const bytes = ethers.getBytes(data);
  const zeroBytes = bytes.reduce((count, byte) => count + (byte === 0 ? 1 : 0), 0);
  const nonzeroBytes = bytes.length - zeroBytes;
  return {
    bytes: bytes.length,
    zeroBytes,
    nonzeroBytes,
    intrinsic: 21_000 + 4 * zeroBytes + 16 * nonzeroBytes,
    floor: 21_000 + 10 * (zeroBytes + 4 * nonzeroBytes),
  };
}

/** Measured gas: label → hardfork → profile → `{gasUsed, calldataBytes, intrinsic, floor, execution}`. */
const GAS = new Map();

/** Records the gas of `receipt`, a transaction on `chain` with calldata `data`, under `label`. */
function recordGas(chain, label, receipt, data) {
  const gasUsed = Number(BigInt(receipt.gasUsed));
  const cost = calldataCost(data);
  const row = GAS.get(label) ?? {};
  row[chain.hardfork] = row[chain.hardfork] ?? {};
  row[chain.hardfork][chain.profile.name] = {
    gasUsed,
    calldataBytes: cost.bytes,
    intrinsic: cost.intrinsic,
    floor: cost.floor,
    execution: gasUsed - cost.intrinsic,
  };
  GAS.set(label, row);
  return gasUsed;
}

/** The recorded gas as `hardfork → label → profile → measurement` (the shape of a gas baseline). */
function gasMeasurements() {
  const report = {};
  for (const [label, row] of [...GAS.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    for (const [hardfork, profiles] of Object.entries(row)) {
      report[hardfork] = report[hardfork] ?? {};
      report[hardfork][label] = profiles;
    }
  }
  return report;
}

/** A Markdown table of the recorded gas used, one row per operation and hardfork. */
function gasReport() {
  const lines = ["| Operation | Hardfork | ETH (chain 1) | BSC (chain 56) |", "|---|---|---|---|"];
  for (const [hardfork, rows] of Object.entries(gasMeasurements())) {
    for (const [label, profiles] of Object.entries(rows)) {
      lines.push(`| ${label} | ${hardfork} | ${profiles.ethereum?.gasUsed ?? "-"} | ${profiles.bsc?.gasUsed ?? "-"} |`);
    }
  }
  return lines.join("\n");
}

/** Writes the recorded gas to the file `SCCP_GAS_REPORT` names, if it is set. */
function writeGasReport() {
  const target = process.env.SCCP_GAS_REPORT;
  if (!target) return;
  fs.writeFileSync(target, `${JSON.stringify(gasMeasurements(), null, 2)}\n`);
}

module.exports = {
  CONTRACT,
  Chain,
  Destination,
  GAS,
  TX_GAS_LIMIT,
  calldataCost,
  compileTestSources,
  createDirectly,
  decodeRevert,
  deploy,
  deployForwarder,
  deploymentOf,
  describeRevert,
  expectRevert,
  expectedRuntime,
  gasMeasurements,
  gasReport,
  immutableWords,
  initCode,
  jsonInteger,
  loadArtifacts,
  recordGas,
  relocate,
  revertData,
  writeGasReport,
};
