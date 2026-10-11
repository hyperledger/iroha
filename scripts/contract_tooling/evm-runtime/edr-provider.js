"use strict";

// Native EDR EIP-1193 test provider. Requires the exact npm-ci-verified 0.12.1
// dependency and its platform Node-API library. No compiler, CLI or network
// server is involved; each provider owns an isolated in-memory test chain.
//
// Every caller states the execution rules: `hardfork` is "prague" or "osaka"
// (no default). Both expose the EIP-2537 BLS12-381 precompiles; Osaka adds the
// EIP-7883 MODEXP pricing and the EIP-7825 transaction gas cap, so gas is
// measured under both (`specs/sccp.md` §5.4). `allowBlocksWithSameTimestamp`
// (default false) lets consecutive blocks share one timestamp for fixture
// replays whose steps repeat a time; block time never decreases either way.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { HDNodeWallet, getBytes } = require("ethers");

const entry = require.resolve("@nomicfoundation/edr");
const packageRoot = path.dirname(entry);
assert.equal(path.basename(packageRoot), "edr");
assert.equal(path.basename(path.dirname(packageRoot)), "@nomicfoundation");
assert.equal(path.basename(path.dirname(path.dirname(packageRoot))), "node_modules");
const descriptor = fs.openSync(path.join(packageRoot, "package.json"),
  fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
let metadata;
try {
  assert(fs.fstatSync(descriptor).isFile(), "native EDR package manifest must be regular");
  metadata = JSON.parse(fs.readFileSync(descriptor, "utf8"));
} finally {
  fs.closeSync(descriptor);
}
assert.equal(metadata.name, "@nomicfoundation/edr");
assert.equal(metadata.version, "0.12.1", "native EDR version must match its audited lock");
const edr = require(entry);
const context = new edr.EdrContext();
const registered = context.registerProviderFactory(edr.L1_CHAIN_TYPE, edr.l1ProviderFactory());
const HARDFORKS = new Map([["prague", edr.SpecId.Prague], ["osaka", edr.SpecId.Osaka]]);
// Public, disposable Ethereum test accounts; never use these keys for real funds.
const accounts = Array.from({ length: 20 }, (_, index) => HDNodeWallet.fromPhrase(
  "test test test test test test test test test test test junk", "", `m/44'/60'/0'/0/${index}`,
));

class NativeEdrProvider {
  constructor({ chainId, blockGasLimit, hardfork, allowBlocksWithSameTimestamp = false }) {
    assert(Number.isSafeInteger(chainId) && chainId > 0, "native EDR requires a positive safe chainId");
    assert(Number.isSafeInteger(blockGasLimit) && blockGasLimit > 0,
      "native EDR requires a positive safe blockGasLimit");
    assert(typeof hardfork === "string" && HARDFORKS.has(hardfork),
      "native EDR requires hardfork \"prague\" or \"osaka\"");
    assert.equal(typeof allowBlocksWithSameTimestamp, "boolean",
      "native EDR allowBlocksWithSameTimestamp must be a boolean");
    this.chainId = chainId;
    this.blockGasLimit = blockGasLimit;
    this.hardfork = hardfork;
    this.allowBlocksWithSameTimestamp = allowBlocksWithSameTimestamp;
    this.provider = null;
    this.closed = false;
    this.startPromise = this.start();
  }

  async start() {
    await registered;
    const specId = HARDFORKS.get(this.hardfork);
    this.provider = await context.createProvider(edr.L1_CHAIN_TYPE, {
      allowBlocksWithSameTimestamp: this.allowBlocksWithSameTimestamp,
      allowUnlimitedContractSize: false,
      bailOnCallFailure: true,
      bailOnTransactionFailure: true,
      chainId: BigInt(this.chainId),
      coinbase: new Uint8Array(20),
      defaultTransactionGasLimit: 16_000_000n,
      genesisState: [
        ...edr.l1GenesisState(specId),
        ...accounts.map((account) => ({ address: getBytes(account.address), balance: 10_000n * 10n ** 18n })),
      ],
      hardfork: edr.l1HardforkToString(specId),
      initialBaseFeePerGas: 1_000_000_000n,
      initialParentBeaconBlockRoot: new Uint8Array(32),
      minGasPrice: 0n,
      mining: {
        autoMine: true,
        blockGasLimit: BigInt(this.blockGasLimit),
        memPool: { order: edr.MineOrdering.Priority },
      },
      network: { genesisBlockGasLimit: BigInt(this.blockGasLimit), genesisBlockTime: 1_783_814_400n },
      networkId: BigInt(this.chainId),
      observability: {},
      ownedAccounts: accounts.map((account) => account.privateKey),
      precompileOverrides: [],
    }, {
      enable: false,
      decodeConsoleLogInputsCallback: () => [],
      printLineCallback: () => {},
    }, { subscriptionCallback: () => {} }, new edr.ContractDecoder());
    const reported = await this.rawRequest("eth_chainId", []);
    assert.equal(BigInt(reported), BigInt(this.chainId), "native EDR reported the wrong chain id");
  }

  async rawRequest(method, params) {
    const response = await this.provider.handleRequest(JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }));
    const payload = typeof response.data === "string" ? JSON.parse(response.data) : response.data;
    if (payload.error) {
      const error = new Error(payload.error.message || "native EDR JSON-RPC error");
      error.code = payload.error.code;
      error.data = payload.error.data;
      throw error;
    }
    return payload.result;
  }

  async request({ method, params = [] }) {
    assert(typeof method === "string" && Array.isArray(params),
      "EIP-1193 request must contain a method and parameter array");
    await this.startPromise;
    assert(!this.closed, "native EDR provider is disconnected");
    return this.rawRequest(method, params);
  }

  async disconnect() {
    await this.startPromise;
    this.closed = true;
    this.provider = null;
  }
}

function createNativeEdrProvider(options) {
  return new NativeEdrProvider(options);
}

module.exports = { createNativeEdrProvider };
