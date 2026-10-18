import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  ToriiHttpError,
  IsoMessageTimeoutError,
  LocalSigningContext,
  NetworkId,
  ToriiClient as BaseToriiClient,
  bootstrapConnectPreviewSession,
  extractToriiFeatureConfig,
  buildRegisterDomainTransaction,
  buildRegisterAccountAndTransferTransaction,
  buildRegisterAssetDefinitionAndMintTransaction,
  buildMintAssetTransaction,
  buildTransferAssetTransaction,
  buildMintAssetInstruction,
  buildTimeTriggerAction,
  buildPacs008Message,
  buildPacs009Message,
  field,
} from "../src/index.js";
import {
  assertNonNegativeInteger,
  isNonEmptyString,
  isPlainObject,
} from "./integrationToriiAssertions.js";
import {
  AuthenticatedIntegrationToriiClient as ToriiClient,
  INTEGRATION_OPERATOR_SIGNING_CONTEXT,
} from "./integrationToriiQueryAuth.js";
import { normalizeIntegrationString, parseBooleanEnv } from "./integrationToriiEnv.js";
import { buildIntegrationGovernancePlainBallotPayload } from "./toriiClientGovernanceTests.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BASE_URL = process.env.IROHA_TORII_INTEGRATION_URL ?? "";
const AUTH_TOKEN = process.env.IROHA_TORII_INTEGRATION_AUTH_TOKEN ?? null;
const API_TOKEN = process.env.IROHA_TORII_INTEGRATION_API_TOKEN ?? null;
const CONFIG_PATH = process.env.IROHA_TORII_INTEGRATION_CONFIG ?? null;
const CONNECT_SESSION = process.env.IROHA_TORII_INTEGRATION_CONNECT_SESSION ?? null;
const ISO_ENABLED = parseBooleanEnv(
  process.env.IROHA_TORII_INTEGRATION_ISO_ENABLED ?? "0",
);
const ISO_ALIAS_LABEL_RAW = process.env.IROHA_TORII_INTEGRATION_ISO_ALIAS ?? "";
const ISO_ALIAS_LABEL =
  ISO_ALIAS_LABEL_RAW.trim().length === 0 ? null : ISO_ALIAS_LABEL_RAW.trim();
const ISO_ALIAS_INDEX_RAW =
  process.env.IROHA_TORII_INTEGRATION_ISO_ALIAS_INDEX ?? "";
const ISO_ALIAS_INDEX =
  ISO_ALIAS_INDEX_RAW.trim().length === 0 ? null : ISO_ALIAS_INDEX_RAW.trim();
const ISO_PACS008_OVERRIDES = parseJsonEnv(
  process.env.IROHA_TORII_INTEGRATION_ISO_PACS008 ?? null,
);
const ISO_PACS009_OVERRIDES = parseJsonEnv(
  process.env.IROHA_TORII_INTEGRATION_ISO_PACS009 ?? null,
);
const ISO_POLL_INTERVAL_MS = parsePositiveIntegerEnv(
  process.env.IROHA_TORII_INTEGRATION_ISO_POLL_MS,
  2_000,
);
const ISO_MAX_ATTEMPTS = parsePositiveIntegerEnv(
  process.env.IROHA_TORII_INTEGRATION_ISO_MAX_ATTEMPTS,
  5,
);
const INTEGRATION_ASSET_DEFINITION_IDS = Object.freeze([
  "62Fk4FPcMuLvW5QjDGNF2a4jAmjM",
  "61CtjvNd9T3THAR65GsMVHr82Bjc",
  "5Pz9SwdN9eXPbiXPX9HRCpzCcE3o",
]);
let randomAssetDefinitionCounter = 0;
const SORAFS_ENABLED = parseBooleanEnv(
  process.env.IROHA_TORII_INTEGRATION_SORAFS_ENABLED ?? "0",
);
const SORAFS_POR_WEEK =
  process.env.IROHA_TORII_INTEGRATION_SORAFS_POR_WEEK ?? null;
const DA_ENABLED = parseBooleanEnv(
  process.env.IROHA_TORII_INTEGRATION_DA_ENABLED ?? "0",
);
const DA_GATEWAY_SPECS = parseJsonEnv(
  process.env.IROHA_TORII_INTEGRATION_DA_GATEWAYS ?? null,
);
const DA_TICKET_RAW = process.env.IROHA_TORII_INTEGRATION_DA_TICKET ?? "";
const DA_TICKET_HEX = DA_TICKET_RAW.trim().length === 0 ? null : DA_TICKET_RAW.trim();
const UAID_LITERAL_RAW = process.env.IROHA_TORII_INTEGRATION_UAID ?? "";
const UAID_LITERAL =
  UAID_LITERAL_RAW.length === 0 ? null : UAID_LITERAL_RAW;
const UAID_DATASPACE_ID = parseUnsignedIntegerEnv(
  process.env.IROHA_TORII_INTEGRATION_UAID_DATASPACE,
  { allowZero: true },
);
const SNS_SUFFIX_ID = parseUnsignedIntegerEnv(
  process.env.IROHA_TORII_INTEGRATION_SNS_SUFFIX,
  { allowZero: true },
);
const SNS_SELECTOR_RAW = process.env.IROHA_TORII_INTEGRATION_SNS_SELECTOR ?? "";
const SNS_SELECTOR =
  SNS_SELECTOR_RAW.trim().length === 0 ? null : SNS_SELECTOR_RAW.trim();
const SPACE_DIRECTORY_ENABLED = parseBooleanEnv(
  process.env.IROHA_TORII_INTEGRATION_SPACE_DIRECTORY_ENABLED ?? "0",
);
const SPACE_DIRECTORY_MANIFEST_PATH =
  process.env.IROHA_TORII_INTEGRATION_SPACE_DIRECTORY_MANIFEST ?? "";
const SPACE_DIRECTORY_REVOKE_EPOCH = parseUnsignedIntegerEnv(
  process.env.IROHA_TORII_INTEGRATION_SPACE_DIRECTORY_REVOKE_EPOCH,
  { allowZero: true },
);
const CONNECT_APP_CONFIG = parseJsonEnv(
  process.env.IROHA_TORII_INTEGRATION_CONNECT_APP ?? null,
);
const CONNECT_PREVIEW_CONFIG = parseJsonEnv(
  process.env.IROHA_TORII_INTEGRATION_CONNECT_PREVIEW ?? null,
);
const CONTRACT_CALL_OPTIONS = parseJsonEnv(
  process.env.IROHA_TORII_INTEGRATION_CONTRACT_CALL ?? null,
);
const GOVERNANCE_BALLOT_OPTIONS = parseJsonEnv(
  process.env.IROHA_TORII_INTEGRATION_GOV_BALLOT ?? null,
);
const NETWORK_ID = NetworkId.parse(
  process.env.IROHA_TORII_INTEGRATION_NETWORK_ID ??
    "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0",
);
const AUTHORITY_ACCOUNT_ID =
  process.env.IROHA_TORII_INTEGRATION_ACCOUNT_ID ??
  "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV";
const PRIVATE_KEY_HEX =
  process.env.IROHA_TORII_INTEGRATION_PRIVATE_KEY_HEX ??
  "802620CCF31D85E3B32A4BEA59987CE0C78E3B8E2DB93881468AB2435FE45D5C9DCD53";
const MUTATION_ENABLED = parseBooleanEnv(process.env.IROHA_TORII_INTEGRATION_MUTATE ?? "0");
const STREAM_ENABLED = parseBooleanEnv(
  process.env.IROHA_TORII_INTEGRATION_STREAM_ENABLED ?? "0",
);
const PROJECT_ROOT = path.resolve(__dirname, "..", "..");

if (!BASE_URL) {
  throw new Error(
    "IROHA_TORII_INTEGRATION_URL is required when the live Torii integration suite is selected",
  );
}

const OPERATOR_CLIENT = new BaseToriiClient(BASE_URL, {
  operatorSigningContext: INTEGRATION_OPERATOR_SIGNING_CONTEXT,
});

const KAIGI_HEALTH_STATUSES = new Set(["healthy", "degraded", "unavailable"]);

/**
 * Integration smoke test that exercises a real Torii instance. The hermetic
 * unit-test profile excludes this file; selecting it without a live URL fails.
 */
test(
  "torii integration smoke test",
  {
    timeout: 60_000,
    todo: false,
  },
  async (t) => {

    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
      localSigningContext: new LocalSigningContext(NETWORK_ID, 753),
    });

    const health = await client.getHealth();
    assert.ok(health, "health snapshot should be present");

    const metricsText = await client.getMetrics({ asText: true });
    assert.equal(typeof metricsText, "string");
    assert.notEqual(metricsText.length, 0);

    const sumeragiStatus = await OPERATOR_CLIENT.getSumeragiStatusTyped();
    assert.equal(sumeragiStatus.protocol_version, 4);
    assert.ok(sumeragiStatus.leader < sumeragiStatus.height_context.validator_count);
    assert.ok(Array.isArray(sumeragiStatus.committed_lane_blocks));

    const connectStatus = await OPERATOR_CLIENT.getConnectStatus();
    assert.ok(connectStatus === null || typeof connectStatus === "object");

    const timeNow = await client.getNetworkTimeNow();
    assertNonNegativeInteger(timeNow.timestampMs, "network time timestampMs");
    assert.ok(
      Number.isInteger(timeNow.offsetMs),
      "network time offsetMs must be an integer",
    );
    assert.ok(
      Number.isInteger(timeNow.confidenceMs) && timeNow.confidenceMs >= 0,
      "network time confidenceMs must be a non-negative integer",
    );

    const timeStatus = await OPERATOR_CLIENT.getNetworkTimeStatus();
    assertNonNegativeInteger(timeStatus.peers, "network time peers");
    assert.ok(Array.isArray(timeStatus.samples), "network time samples must be an array");
    timeStatus.samples.forEach((sample, index) => {
      assert.equal(
        typeof sample.peer,
        "string",
        `network time samples[${index}].peer must be a string`,
      );
      assert.notEqual(
        sample.peer.length,
        0,
        `network time samples[${index}].peer must be non-empty`,
      );
      assert.ok(
        Number.isInteger(sample.lastOffsetMs),
        `network time samples[${index}].lastOffsetMs must be an integer`,
      );
      assert.ok(
        Number.isInteger(sample.lastRttMs) && sample.lastRttMs >= 0,
        `network time samples[${index}].lastRttMs must be a non-negative integer`,
      );
      assertNonNegativeInteger(
        sample.count,
        `network time samples[${index}].count`,
      );
    });
    assert.ok(timeStatus.rtt && typeof timeStatus.rtt === "object", "network time rtt payload");
    assert.ok(
      Array.isArray(timeStatus.rtt.buckets),
      "network time rtt buckets must be an array",
    );
    timeStatus.rtt.buckets.forEach((bucket, index) => {
      assert.equal(
        typeof bucket,
        "object",
        `network time rtt buckets[${index}] must be an object`,
      );
      assert.ok(
        Number.isInteger(bucket.le),
        `network time rtt buckets[${index}].le must be an integer`,
      );
      assertNonNegativeInteger(
        bucket.count,
        `network time rtt buckets[${index}].count`,
      );
    });
    assertNonNegativeInteger(timeStatus.rtt.sumMs, "network time rtt sumMs");
    assertNonNegativeInteger(timeStatus.rtt.count, "network time rtt count");
    if (timeStatus.note !== undefined && timeStatus.note !== null) {
      assert.equal(
        typeof timeStatus.note,
        "string",
        "network time status note must be a string when present",
      );
    }

    if (CONFIG_PATH) {
      const resolved = path.resolve(CONFIG_PATH);
      const configRaw = fs.readFileSync(resolved, "utf8");
      const configData = JSON.parse(configRaw);
      const features = extractToriiFeatureConfig({ config: configData });
      assert.ok("isoBridge" in features);
      assert.equal("rbcSampling" in features, false);
      assert.ok("connect" in features);
    }

    if (CONNECT_SESSION) {
      const rawSessionOptions = JSON.parse(CONNECT_SESSION);
      for (const field of ["sid", "network_id", "app_pk", "nonce"]) {
        assert.ok(rawSessionOptions[field], `connect session payload must provide ${field}`);
      }
      const session = await client.createConnectSession({
        sid: rawSessionOptions.sid,
        networkId: NetworkId.parse(rawSessionOptions.network_id),
        appPublicKey: Buffer.from(rawSessionOptions.app_pk, "base64url"),
        nonce: Buffer.from(rawSessionOptions.nonce, "base64url"),
        node: rawSessionOptions.node ?? null,
      });
      assert.ok(session?.wallet_uri ?? session?.walletUri, "connect session should return a wallet URI");
    }
  },
);

test(
  "status snapshot exposes governance and queue metrics",
  {
    timeout: 60_000,
  },
  async (t) => {
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
      localSigningContext: new LocalSigningContext(NETWORK_ID, 753),
    });
    const snapshot = await client.getStatusSnapshot();
    assert.ok(snapshot, "status snapshot response must be present");
    assert.equal(typeof snapshot.timestamp, "number", "snapshot timestamp should be numeric");

    const { status, metrics } = snapshot;
    assert.ok(status && typeof status === "object", "status payload should be an object");
    assert.ok(metrics && typeof metrics === "object", "status metrics should be an object");

    assert.equal(typeof status.peers, "number");
    assert.equal(typeof status.queue_size, "number");
    assert.equal(typeof status.commit_time_ms, "number");
    assert.ok(Array.isArray(status.lane_governance), "lane governance entries must be an array");
    assert.ok(
      Array.isArray(status.lane_governance_sealed_aliases),
      "lane governance sealed aliases must be an array",
    );
    assert.equal(Object.hasOwn(status, "lane_commitments"), false);
    assert.equal(Object.hasOwn(status, "dataspace_commitments"), false);
    assert.equal(Object.hasOwn(status, "pipeline_execution"), false);

    assert.equal(typeof metrics.commit_latency_ms, "number");
    assert.equal(typeof metrics.queue_size, "number");
    assert.equal(typeof metrics.queue_delta, "number");
    assert.equal(typeof metrics.tx_approved_delta, "number");
    assert.equal(typeof metrics.tx_rejected_delta, "number");
    assert.equal(typeof metrics.view_change_delta, "number");
    assert.equal(typeof metrics.has_activity, "boolean");

    if (status.governance) {
      const {
        proposals,
        protected_namespace: protectedNamespace,
        manifest_admission: manifestAdmission,
        manifest_quorum: manifestQuorum,
        recent_manifest_activations: activations,
      } = status.governance;

      assertNonNegativeInteger(
        proposals.proposed,
        "governance.proposals.proposed",
      );
      assertNonNegativeInteger(
        proposals.rejected,
        "governance.proposals.rejected",
      );
      assertNonNegativeInteger(
        proposals.enacted,
        "governance.proposals.enacted",
      );
      assertNonNegativeInteger(
        proposals.superseded,
        "governance.proposals.superseded",
      );
      assertNonNegativeInteger(
        proposals.execution_failed,
        "governance.proposals.execution_failed",
      );

      assertNonNegativeInteger(
        protectedNamespace.total_checks,
        "governance.protected_namespace.total_checks",
      );
      assertNonNegativeInteger(
        protectedNamespace.allowed,
        "governance.protected_namespace.allowed",
      );
      assertNonNegativeInteger(
        protectedNamespace.rejected,
        "governance.protected_namespace.rejected",
      );

      assertNonNegativeInteger(
        manifestAdmission.total_checks,
        "governance.manifest_admission.total_checks",
      );
      assertNonNegativeInteger(
        manifestAdmission.allowed,
        "governance.manifest_admission.allowed",
      );
      assertNonNegativeInteger(
        manifestAdmission.quorum_rejected,
        "governance.manifest_admission.quorum_rejected",
      );

      assertNonNegativeInteger(
        manifestQuorum.total_checks,
        "governance.manifest_quorum.total_checks",
      );
      assertNonNegativeInteger(
        manifestQuorum.allowed,
        "governance.manifest_quorum.allowed",
      );
      assertNonNegativeInteger(
        manifestQuorum.rejected,
        "governance.manifest_quorum.rejected",
      );

      assert.ok(
        Array.isArray(activations),
        "governance recent activations must be an array when provided",
      );
    } else {
      t.diagnostic("status snapshot did not include governance counters");
    }
  },
);

test(
  "peer metadata endpoints return typed payloads",
  {
    timeout: 60_000,
  },
  async (t) => {
    const peers = await OPERATOR_CLIENT.listPeersTyped();
    assert.ok(Array.isArray(peers), "peer listing must return an array");
    if (peers.length === 0) {
      t.diagnostic("listPeersTyped returned an empty array; skipping shape assertions");
    } else {
      for (const peer of peers) {
        assert.equal(typeof peer.address, "string");
        assert.notEqual(peer.address.length, 0);
        assert.equal(typeof peer.public_key_hex, "string");
        assert.equal(peer.public_key_hex.length, 64);
      }
    }

    const telemetryPeers = await client.listTelemetryPeersInfo();
    assert.ok(
      Array.isArray(telemetryPeers),
      "telemetry peer listing must return an array",
    );
    if (telemetryPeers.length === 0) {
      t.diagnostic(
        "listTelemetryPeersInfo returned an empty array; skipping telemetry shape assertions",
      );
      return;
    }

    for (const entry of telemetryPeers) {
      assert.equal(typeof entry.url, "string");
      assert.notEqual(entry.url.length, 0);
      assert.equal(typeof entry.connected, "boolean");
      if (entry.config) {
        assert.equal(typeof entry.config.publicKey, "string");
        assert.notEqual(entry.config.publicKey.length, 0);
      }
      if (entry.location) {
        assert.equal(typeof entry.location.countryCode, "string");
        assert.notEqual(entry.location.countryCode.length, 0);
      }
      if (entry.connectedPeers) {
        assert.ok(Array.isArray(entry.connectedPeers));
        for (const peerUrl of entry.connectedPeers) {
          assert.equal(typeof peerUrl, "string");
          assert.notEqual(peerUrl.length, 0);
        }
      }
    }
  },
);

test(
  "block list endpoint returns pagination metadata",
  {
    timeout: 60_000,
  },
  async (t) => {
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
    });
    const page = await client.explorerBlocks.list({ limit: 5 });
    assert.ok(page, "blocks page payload must be present");
    const { nextCursor, items } = page;
    assert.ok(nextCursor === null || typeof nextCursor === "string");
    assert.ok(Array.isArray(items), "block list should return an items array");
    assert.ok(items.length <= 5, "block list must respect provided limit");
    if (items.length === 0) {
      t.diagnostic("block list returned zero entries");
      return;
    }

    const first = items[0];
    assert.equal(typeof first.hash, "string", "block hash must be a string");
    assertNonNegativeInteger(first.height, "blocks.items[0].height");
    assert.equal(typeof first.createdAt, "string", "block createdAt must be a string");
    assert.equal(
      typeof first.transactionsTotal,
      "number",
      "block transactionsTotal must be numeric",
    );
    const fetched = await client.getBlock(first.height);
    assert.ok(fetched, "getBlock should return payload for heights returned by listBlocks");
    assert.equal(fetched.hash, first.hash, "block hash should match the list entry");
    assert.equal(fetched.height, first.height, "block height should match the list entry");
  },
);

test(
  "account permission endpoints expose authority tokens",
  {
    timeout: 60_000,
  },
  async (t) => {
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
    });
    const accountId = AUTHORITY_ACCOUNT_ID;
    const page = await client.accountPermissions(accountId).list({ limit: 10, includeTotal: true });
    assert.ok(page, "account permission list should return a payload");
    assert.ok(
      typeof page.total === "number",
      "account permission payload should expose a total count",
    );
    assert.ok(
      Array.isArray(page.items),
      "account permission payload should expose an items array",
    );
    if (page.items.length === 0) {
      t.diagnostic(
        "authority account reported zero permission tokens; skipping iterator assertions",
      );
      return;
    }
    const sample = page.items[0];
    assert.equal(typeof sample.name, "string", "permission token must include a name");
    assert.notEqual(sample.name.length, 0, "permission token name must be non-empty");
    if (sample.payload !== null && sample.payload !== undefined) {
      assert.equal(
        typeof sample.payload,
        "object",
        "permission token payload must be an object when present",
      );
    }
    const limitedPage = await client.accountPermissions(accountId).list({ limit: 1 });
    assert.ok(
      Array.isArray(limitedPage.items),
      "account permission list should respect pagination parameters",
    );
    assert.ok(
      limitedPage.items.length <= 1,
      "account permission list must respect the provided limit",
    );
    const iteratorIncludesSample = await iteratorIncludes(
      client.accountPermissions(accountId).iterate({ limit: 2 }),
      (entry) => entry?.name === sample.name,
    );
    assert.ok(
      iteratorIncludesSample,
      "account permission iterator should surface entries returned by the permission collection",
    );
  },
);

test(
  "configuration snapshot returns JSON payload (optional)",
  {
    timeout: 30_000,
  },
  async (t) => {
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
    });
    const config = await client.getConfiguration();
    if (!config) {
      t.diagnostic("Torii configuration endpoint unavailable on target node");
      return;
    }
    assert.equal(typeof config, "object", "configuration snapshot must be an object");
    assert.ok(
      Object.keys(config).length > 0,
      "configuration snapshot should include at least one field",
    );
  },
);

test(
  "confidential gas schedule helper reports numeric fields (optional)",
  {
    timeout: 30_000,
  },
  async (t) => {
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
    });
    const gasSchedule = await client.getConfidentialGasSchedule();
    if (!gasSchedule) {
      t.diagnostic(
        "Torii configuration did not expose a confidential gas schedule; skipping numeric assertions",
      );
      return;
    }
    assertNonNegativeNumber(gasSchedule.proofBase, "gasSchedule.proofBase");
    assertNonNegativeNumber(gasSchedule.perPublicInput, "gasSchedule.perPublicInput");
    assertNonNegativeNumber(gasSchedule.perProofByte, "gasSchedule.perProofByte");
    assertNonNegativeNumber(gasSchedule.perNullifier, "gasSchedule.perNullifier");
    assertNonNegativeNumber(gasSchedule.perCommitment, "gasSchedule.perCommitment");
  },
);

test(
  "node capabilities and runtime ABI endpoints respond",
  {
    timeout: 60_000,
  },
  async (t) => {
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
    });

    const capabilities = await client.getNodeCapabilities();
    assertNonNegativeInteger(
      capabilities.abiVersion,
      "node capabilities abiVersion",
    );
    assertNonNegativeInteger(
      capabilities.dataModelVersion,
      "node capabilities dataModelVersion",
    );
    assert.equal(typeof capabilities.crypto, "object", "crypto capabilities must exist");
    assert.equal(
      typeof capabilities.crypto.sm.enabled,
      "boolean",
      "SM capability flag must be boolean",
    );
    assert.ok(
      Array.isArray(capabilities.crypto.sm.allowedSigning),
      "SM allowedSigning list must be an array",
    );
    assert.ok(
      Array.isArray(capabilities.crypto.curves.allowedCurveIds),
      "curve capability list must be an array",
    );

    const abiActive = await client.getRuntimeAbiActive();
    assertNonNegativeInteger(
      abiActive.abiVersion,
      "runtime ABI abiVersion",
    );

    const abiHash = await client.getRuntimeAbiHash();
    assert.ok(abiHash.policy, "runtime ABI hash response must include policy label");
    assertHexString(abiHash.abiHashHex, "runtime ABI hash hex");

    const runtimeMetrics = await client.getRuntimeMetrics();
    assertNonNegativeInteger(
      runtimeMetrics.abiVersion,
      "runtime metrics abiVersion",
    );
    assert.equal(
      typeof runtimeMetrics.upgradeEventsTotal.proposed,
      "number",
      "runtime metrics upgradeEventsTotal.proposed must be numeric",
    );
    assert.equal(
      typeof runtimeMetrics.upgradeEventsTotal.activated,
      "number",
      "runtime metrics upgradeEventsTotal.activated must be numeric",
    );
    assert.equal(
      typeof runtimeMetrics.upgradeEventsTotal.canceled,
      "number",
      "runtime metrics upgradeEventsTotal.canceled must be numeric",
    );

    const runtimeUpgrades = await client.listRuntimeUpgrades();
    assert.ok(Array.isArray(runtimeUpgrades), "runtime upgrades list must be an array");
    if (runtimeUpgrades.length > 0) {
      const entry = runtimeUpgrades[0];
      assertHexString(entry.idHex, "runtime upgrade idHex");
      assert.ok(
        entry.record?.manifest?.name,
        "runtime upgrade entries must expose manifest metadata",
      );
    } else {
      t.diagnostic("runtime upgrades list is empty on target node");
    }
  },
);

test(
  "sumeragi evidence list/count endpoints respond",
  {
    timeout: 60_000,
  },
  async (t) => {
    const count = await OPERATOR_CLIENT.getSumeragiEvidenceCount();
    assertEvidenceU64(count.count, "sumeragi evidence count");

    const page = await OPERATOR_CLIENT.listSumeragiEvidence({ limit: 5 });
    assertEvidenceU64(page.total, "sumeragi evidence total");
    assert.ok(Array.isArray(page.items), "sumeragi evidence items must be an array");
    assert.ok(
      page.items.length <= 5,
      "sumeragi evidence list should respect the provided limit",
    );
    if (page.items.length === 0) {
      t.diagnostic("no consensus evidence entries returned by the target node");
      return;
    }
    for (const entry of page.items) {
      assertEvidenceRecord(entry);
    }
  },
);

test(
  "nft list and query endpoints respond (optional)",
  {
    timeout: 60_000,
  },
  async (t) => {
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
    });

    let listPage;
    try {
      listPage = await client.nfts.list({ limit: 5, includeTotal: true });
    } catch (error) {
      if (isUnexpectedNotFoundError(error)) {
        t.diagnostic(
          `NFT list endpoint unavailable on target node: ${
            error instanceof Error ? error.message : String(error)
          }`,
        );
        return;
      }
      throw error;
    }
    assertNonNegativeInteger(listPage.total, "nft list total");
    assert.ok(Array.isArray(listPage.items), "nft list must expose items array");
    if (listPage.items.length === 0) {
      t.diagnostic("NFT list returned zero entries; skipping filter assertions");
    } else {
      const entry = listPage.items[0];
      assert.equal(typeof entry.id, "string", "nft list entry id must be a string");
      assert.notEqual(entry.id.length, 0, "nft list entry id must not be empty");
    }

    let queryPage;
    try {
      queryPage = await client.nfts.list({ limit: 5, sort: "id", includeTotal: true });
    } catch (error) {
      if (isUnexpectedNotFoundError(error)) {
        t.diagnostic(
          `NFT query endpoint unavailable on target node: ${
            error instanceof Error ? error.message : String(error)
          }`,
        );
        return;
      }
      throw error;
    }
    assertNonNegativeInteger(queryPage.total, "nft query total");
    assert.ok(Array.isArray(queryPage.items), "nft query must expose items array");

    const referenceId =
      listPage.items.find((entry) => entry?.id)?.id ??
      queryPage.items.find((entry) => entry?.id)?.id ??
      null;
    if (referenceId) {
      assert.ok(
        queryPage.items.some((entry) => entry?.id === referenceId),
        "nft query should include at least one known id",
      );
      const iteratorListFound = await iteratorIncludes(
        client.nfts.iterate({ limit: 2 }),
        (entry) => entry?.id === referenceId,
      );
      assert.ok(iteratorListFound, "nft iterator should surface the reference id");
      const iteratorQueryFound = await iteratorIncludes(
        client.nfts.iterate({ filter: field("id").eq(referenceId), limit: 2 }),
        (entry) => entry?.id === referenceId,
      );
      assert.ok(iteratorQueryFound, "filtered nft iterator should surface the reference id");
    } else {
      t.diagnostic("NFT endpoints returned empty payloads; iterator assertions skipped");
      for await (const _unused of client.nfts.iterate({ limit: 2 })) {
        t.diagnostic(`drained nft iterator item: ${JSON.stringify(_unused)}`);
        break;
      }
    }
  },
);

test(
  "register domain via pipeline and fetch via listDomains",
  {
    timeout: 90_000,
  },
  async (t) => {
    if (!MUTATION_ENABLED) {
      t.diagnostic("set IROHA_TORII_INTEGRATION_MUTATE=1 to enable mutation coverage");
      return;
    }
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
    });
    if (!PRIVATE_KEY_HEX) {
      t.diagnostic("IROHA_TORII_INTEGRATION_PRIVATE_KEY_HEX is required for mutation coverage");
      return;
    }
    const privateKey = decodePrivateKeyHex(PRIVATE_KEY_HEX);
    const domainId = randomDomainId();
    const { signedTransaction, hash } = buildRegisterDomainTransaction({
      networkId: NETWORK_ID,
      authority: AUTHORITY_ACCOUNT_ID,
      domainId,
      metadata: {
        suite: "js-integration",
        timestamp: Date.now(),
      },
      privateKey,
    });

    const status = await client.submitTransactionAndWait(signedTransaction, {
      hashHex: hash.toString("hex"),
      intervalMs: 1_000,
      timeoutMs: 30_000,
    });
    assertSuccessfulStatus(status, domainId);

    let found = false;
    for await (const entry of client.domains.iterate({
      filter: field("id").eq(domainId),
      limit: 5,
    })) {
      if (entry?.id === domainId) {
        found = true;
        break;
      }
    }
    assert.ok(found, `expected the domains collection to include ${domainId}`);
  },
);

test(
  "pipeline status endpoints surface typed payloads",
  {
    timeout: 90_000,
  },
  async (t) => {
    if (!MUTATION_ENABLED) {
      t.diagnostic("set IROHA_TORII_INTEGRATION_MUTATE=1 to enable mutation coverage");
      return;
    }
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
    });
    if (!PRIVATE_KEY_HEX) {
      t.diagnostic("IROHA_TORII_INTEGRATION_PRIVATE_KEY_HEX is required for mutation coverage");
      return;
    }
    const privateKey = decodePrivateKeyHex(PRIVATE_KEY_HEX);
    const domainId = randomDomainId();
    const { signedTransaction, hash } = buildRegisterDomainTransaction({
      networkId: NETWORK_ID,
      authority: AUTHORITY_ACCOUNT_ID,
      domainId,
      metadata: {
        suite: "js-integration",
        step: "pipeline-status",
        timestamp: Date.now(),
      },
      privateKey,
    });
    const hashHex = hash.toString("hex");

    await client.submitTransaction(signedTransaction);

    const typedStatus = await client.waitForTransactionStatus(hashHex, {
      intervalMs: 1_000,
      timeoutMs: 60_000,
    });
    assertSuccessfulStatus(typedStatus, domainId);
    assert.equal(
      typedStatus.hash,
      hashHex,
      "pipeline status payload should expose the submitted hash",
    );
    assert.equal(typedStatus.status.kind, "Applied");
    assert.equal(typedStatus.scope, "global");
    assert.equal(typedStatus.resolved_from, "state");

    const fetchedStatus = await client.getTransactionStatus(hashHex);
    assert.ok(
      fetchedStatus,
      "pipeline status endpoint should retain the terminal snapshot after polling",
    );
    assert.equal(
      fetchedStatus?.hash,
      hashHex,
      "fetching the pipeline status should return the same transaction hash",
    );
    assert.equal(
      fetchedStatus?.status?.kind,
      typedStatus?.status?.kind,
      "fetching the pipeline status should preserve the Applied status kind",
    );
  },
);

test(
  "register account, mint asset, and inspect balances",
  {
    timeout: 120_000,
  },
  async (t) => {
    if (!MUTATION_ENABLED) {
      t.diagnostic("set IROHA_TORII_INTEGRATION_MUTATE=1 to enable mutation coverage");
      return;
    }
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
    });
    if (!PRIVATE_KEY_HEX) {
      t.diagnostic("IROHA_TORII_INTEGRATION_PRIVATE_KEY_HEX is required for mutation coverage");
      return;
    }
    const privateKey = decodePrivateKeyHex(PRIVATE_KEY_HEX);
    const accountId = randomAccountId();
    const { signedTransaction: accountTx, hash: accountHash } =
      buildRegisterAccountAndTransferTransaction({
        networkId: NETWORK_ID,
        authority: AUTHORITY_ACCOUNT_ID,
        account: {
          accountId,
          metadata: {
            suite: "js-integration",
            step: "account-asset",
          },
        },
        privateKey,
      });
    const accountStatus = await client.submitTransactionAndWait(accountTx, {
      hashHex: accountHash.toString("hex"),
      intervalMs: 1_000,
      timeoutMs: 30_000,
    });
    assertSuccessfulStatus(accountStatus, accountId);

    const assetDefinitionId = randomAssetDefinitionId();
    const assetId = composeAssetId(assetDefinitionId, AUTHORITY_ACCOUNT_ID);
    const { signedTransaction: assetTx, hash: assetHash } =
      buildRegisterAssetDefinitionAndMintTransaction({
        networkId: NETWORK_ID,
        authority: AUTHORITY_ACCOUNT_ID,
        assetDefinition: {
          assetDefinitionId,
          name: "integration_asset_mint",
          owningDomain: null,
          balanceScopePolicy: "Global",
          metadata: {
            suite: "js-integration",
            step: "asset-mint",
          },
        },
        mint: {
          assetId,
          quantity: "7",
        },
        privateKey,
      });
    const assetStatus = await client.submitTransactionAndWait(assetTx, {
      hashHex: assetHash.toString("hex"),
      intervalMs: 1_000,
      timeoutMs: 30_000,
    });
    assertSuccessfulStatus(assetStatus, assetDefinitionId);

    let definitionFound = false;
    for await (const definition of client.assetDefinitions.iterate({
      filter: field("id").eq(assetDefinitionId),
      limit: 5,
    })) {
      if (definition?.id === assetDefinitionId) {
        definitionFound = true;
        break;
      }
    }
    assert.ok(definitionFound, `expected asset definitions to include ${assetDefinitionId}`);

    const assetFound = await findAccountAsset(client, accountId, assetId);
    assert.ok(assetFound, `expected ${accountId} to own ${assetId}`);
    assert.equal(assetFound.quantity, "7");

    const { signedTransaction: extraMintTx, hash: extraMintHash } =
      buildMintAssetTransaction({
        networkId: NETWORK_ID,
        authority: AUTHORITY_ACCOUNT_ID,
        assetId,
        quantity: "3",
        metadata: {
          suite: "js-integration",
          step: "asset-remint",
        },
        privateKey,
      });
    const extraMintStatus = await client.submitTransactionAndWait(extraMintTx, {
      hashHex: extraMintHash.toString("hex"),
      intervalMs: 1_000,
      timeoutMs: 30_000,
    });
    assertSuccessfulStatus(extraMintStatus, assetId);

    const refreshedAsset = await findAccountAsset(client, accountId, assetId);
    assert.ok(refreshedAsset, `expected refreshed asset snapshot for ${assetId}`);
    assert.equal(refreshedAsset.quantity, "10");

    const domainQueryFound = await iteratorIncludes(
      client.domains.iterate({ limit: 5 }),
      (domain) => domain?.id === domainId,
    );
    assert.ok(domainQueryFound, `expected domain iterator to include ${domainId}`);

    const accountQueryFound = await iteratorIncludes(
      client.accounts.iterate({ limit: 5 }),
      (account) => account?.id === accountId,
    );
    assert.ok(accountQueryFound, `expected account iterator to include ${accountId}`);

    const assetDefinitionQueryFound = await iteratorIncludes(
      client.assetDefinitions.iterate({ limit: 5 }),
      (definition) => definition?.id === assetDefinitionId,
    );
    assert.ok(
      assetDefinitionQueryFound,
      `expected asset definition query iterator to include ${assetDefinitionId}`,
    );

    const accountTransactions = await client.accountTransactions(accountId).list({
      limit: 5,
    });
    assert.ok(
      Array.isArray(accountTransactions?.items) && accountTransactions.items.length > 0,
      "account transactions list should include at least one entry",
    );

    const accountAssetQuery = await client.accountAssets(accountId).list({
      limit: 5,
      sort: "-quantity",
      includeTotal: true,
    });
    assert.ok(
      accountAssetQuery && typeof accountAssetQuery.total === "number",
      "account asset query response should expose totals",
    );
    assert.ok(
      Array.isArray(accountAssetQuery.items) && accountAssetQuery.items.length > 0,
      "account asset query response should include an items array",
    );
    assert.ok(
      accountAssetQuery.items.some((entry) => entry?.asset === assetDefinitionOf(assetId)),
      `expected account asset query results to include ${assetId}`,
    );

    const assetQueryIteratorFound = await iteratorIncludes(
      client.accountAssets(accountId).iterate({ limit: 2 }),
      (entry) => entry?.asset === assetDefinitionOf(assetId),
    );
    assert.ok(
      assetQueryIteratorFound,
      `expected account asset query iterator to include ${assetId}`,
    );
  },
);

test(
  "transfer asset between accounts and verify balances",
  {
    timeout: 120_000,
  },
  async (t) => {
    if (!MUTATION_ENABLED) {
      t.diagnostic("set IROHA_TORII_INTEGRATION_MUTATE=1 to enable mutation coverage");
      return;
    }
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
    });
    if (!PRIVATE_KEY_HEX) {
      t.diagnostic("IROHA_TORII_INTEGRATION_PRIVATE_KEY_HEX is required for mutation coverage");
      return;
    }
    const privateKey = decodePrivateKeyHex(PRIVATE_KEY_HEX);
    const senderAccountId = randomAccountId();
    const receiverAccountId = randomAccountId();
    const assetDefinitionId = randomAssetDefinitionId();
    const senderAssetId = composeAssetId(assetDefinitionId, senderAccountId);
    const receiverAssetId = composeAssetId(assetDefinitionId, receiverAccountId);
    const mintedQuantity = "15";
    const transferQuantity = "6";
    const remainingQuantity = (BigInt(mintedQuantity) - BigInt(transferQuantity)).toString();

    const { signedTransaction: senderTx, hash: senderHash } =
      buildRegisterAccountAndTransferTransaction({
        networkId: NETWORK_ID,
        authority: AUTHORITY_ACCOUNT_ID,
        account: {
          accountId: senderAccountId,
          metadata: {
            suite: "js-integration",
            step: "asset-transfer",
            role: "sender",
          },
        },
        privateKey,
      });
    const senderStatus = await client.submitTransactionAndWait(senderTx, {
      hashHex: senderHash.toString("hex"),
      intervalMs: 1_000,
      timeoutMs: 30_000,
    });
    assertSuccessfulStatus(senderStatus, senderAccountId);

    const { signedTransaction: receiverTx, hash: receiverHash } =
      buildRegisterAccountAndTransferTransaction({
        networkId: NETWORK_ID,
        authority: AUTHORITY_ACCOUNT_ID,
        account: {
          accountId: receiverAccountId,
          metadata: {
            suite: "js-integration",
            step: "asset-transfer",
            role: "receiver",
          },
        },
        privateKey,
      });
    const receiverStatus = await client.submitTransactionAndWait(receiverTx, {
      hashHex: receiverHash.toString("hex"),
      intervalMs: 1_000,
      timeoutMs: 30_000,
    });
    assertSuccessfulStatus(receiverStatus, receiverAccountId);

    const { signedTransaction: assetTx, hash: assetHash } =
      buildRegisterAssetDefinitionAndMintTransaction({
        networkId: NETWORK_ID,
        authority: AUTHORITY_ACCOUNT_ID,
        assetDefinition: {
          assetDefinitionId,
          name: "integration_asset_transfer",
          owningDomain: null,
          balanceScopePolicy: "Global",
          metadata: {
            suite: "js-integration",
            step: "asset-transfer",
          },
        },
        mint: {
          accountId: senderAccountId,
          quantity: mintedQuantity,
        },
        privateKey,
      });
    const assetStatus = await client.submitTransactionAndWait(assetTx, {
      hashHex: assetHash.toString("hex"),
      intervalMs: 1_000,
      timeoutMs: 30_000,
    });
    assertSuccessfulStatus(assetStatus, assetDefinitionId);

    const mintedAsset = await findAccountAsset(client, senderAccountId, senderAssetId);
    assert.ok(mintedAsset, `expected minted asset snapshot for ${senderAssetId}`);
    assert.equal(mintedAsset.quantity, mintedQuantity);

    const { signedTransaction: transferTx, hash: transferHash } = buildTransferAssetTransaction({
      networkId: NETWORK_ID,
      authority: AUTHORITY_ACCOUNT_ID,
      sourceAssetId: senderAssetId,
      destinationAccountId: receiverAccountId,
      quantity: transferQuantity,
      metadata: {
        suite: "js-integration",
        step: "asset-transfer",
      },
      privateKey,
    });
    const transferStatus = await client.submitTransactionAndWait(transferTx, {
      hashHex: transferHash.toString("hex"),
      intervalMs: 1_000,
      timeoutMs: 30_000,
    });
    assertSuccessfulStatus(transferStatus, senderAssetId);

    const senderSnapshot = await findAccountAsset(client, senderAccountId, senderAssetId);
    assert.ok(senderSnapshot, `expected refreshed asset snapshot for ${senderAssetId}`);
    assert.equal(senderSnapshot.quantity, remainingQuantity);

    const receiverSnapshot = await findAccountAsset(client, receiverAccountId, receiverAssetId);
    assert.ok(receiverSnapshot, `expected receiver asset snapshot for ${receiverAssetId}`);
    assert.equal(receiverSnapshot.quantity, transferQuantity);

    const receiverAssets = await client.accountAssets(receiverAccountId).list({ limit: 5 });
    const receiverItems = receiverAssets?.items ?? [];
    assert.ok(Array.isArray(receiverItems), "account asset list should expose items");
    assert.ok(
      receiverItems.some((entry) => entry?.asset === assetDefinitionOf(receiverAssetId)),
      `expected account asset list to include ${receiverAssetId}`,
    );

    const holderPage = await client.assetHolders(assetDefinitionId).list({ limit: 10 });
    assert.ok(
      holderPage && Array.isArray(holderPage.items),
      "asset holder list should return entries",
    );
    const senderHolder = holderPage.items.find(
      (entry) => entry?.account_id === senderAccountId,
    );
    assert.ok(senderHolder, `expected holders list to include ${senderAccountId}`);
    assert.equal(
      senderHolder.quantity,
      remainingQuantity,
      "sender holder entry must report remaining quantity",
    );
    const receiverHolder = holderPage.items.find(
      (entry) => entry?.account_id === receiverAccountId,
    );
    assert.ok(receiverHolder, `expected holders list to include ${receiverAccountId}`);
    assert.equal(
      receiverHolder.quantity,
      transferQuantity,
      "receiver holder entry must report transferred quantity",
    );

    const holderQuery = await client.assetHolders(assetDefinitionId).list({
      limit: 5,
      sort: "-quantity",
      includeTotal: true,
    });
    assert.ok(
      holderQuery && typeof holderQuery.total === "number",
      "asset holder query should return a payload with totals",
    );
    assert.ok(
      Array.isArray(holderQuery.items) && holderQuery.items.length > 0,
      "asset holder query should expose an items array",
    );
    const holderQueryIncludesReceiver = holderQuery.items.some(
      (entry) => entry?.account_id === receiverAccountId,
    );
    assert.ok(
      holderQueryIncludesReceiver,
      `asset holder query should include ${receiverAccountId}`,
    );

    const iteratorListFound = await iteratorIncludes(
      client.assetHolders(assetDefinitionId).iterate({ limit: 5 }),
      (entry) => entry?.account_id === receiverAccountId && entry.quantity === transferQuantity,
    );
    assert.ok(iteratorListFound, "asset holder iterator should surface the receiver account");

    const iteratorQueryFound = await iteratorIncludes(
      client.assetHolders(assetDefinitionId).iterate({
        filter: field("account_id").eq(senderAccountId),
        limit: 5,
      }),
      (entry) => entry?.account_id === senderAccountId && entry.quantity === remainingQuantity,
    );
    assert.ok(iteratorQueryFound, "filtered asset holder iterator should surface the sender account");

    const accountFilter = field("id").eq(senderAccountId);
    const accountList = await client.accounts.list({ filter: accountFilter, limit: 5 });
    const accountListItems = accountList?.items ?? [];
    assert.ok(
      accountListItems.some((entry) => entry?.id === senderAccountId),
      "account list should surface the sender account",
    );

    const accountQueryPage = await client.accounts.list({ filter: accountFilter.toString(), limit: 1 });
    const accountQueryItems = accountQueryPage?.items ?? [];
    assert.ok(
      accountQueryItems.length >= 1 && accountQueryItems[0]?.id === senderAccountId,
      "account query should return the sender account as the first entry",
    );

    const listIteratorFound = await iteratorIncludes(
      client.accounts.iterate({ filter: accountFilter, limit: 5 }),
      (entry) => entry?.id === senderAccountId,
    );
    assert.ok(listIteratorFound, "account iterator should include the sender account");

    const queryIteratorFound = await iteratorIncludes(
      client.accounts.iterate({ filter: accountFilter.toJSON(), limit: 5 }),
      (entry) => entry?.id === senderAccountId,
    );
    assert.ok(
      queryIteratorFound,
      "account query iterator should include the sender account",
    );

    const i105AccountList = await client.accounts.list({
      filter: accountFilter,
      limit: 5,
    });
    const i105AccountItems = i105AccountList?.items ?? [];
    assert.ok(
      i105AccountItems.some((entry) => entry?.id === senderAccountId),
      "account list should honour i105 address formatting",
    );

    const i105AccountQuery = await client.accounts.list({
      filter: accountFilter,
      limit: 1,
    });
    const i105QueryItems = i105AccountQuery?.items ?? [];
    assert.ok(
      i105QueryItems.length > 0 && i105QueryItems[0]?.id === senderAccountId,
      "account query should return i105 literals when requested",
    );

    const i105ListIteratorFound = await iteratorIncludes(
      client.accounts.iterate({
        filter: accountFilter,
        limit: 5,
      }),
      (entry) => entry?.id === senderAccountId,
    );
    assert.ok(
      i105ListIteratorFound,
      "account iterator should emit i105 literals when requested",
    );

    const i105QueryIteratorFound = await iteratorIncludes(
      client.accounts.iterate({
        filter: accountFilter,
        sort: "id",
        limit: 5,
      }),
      (entry) => entry?.id === senderAccountId,
    );
    assert.ok(
      i105QueryIteratorFound,
      "account query iterator should emit i105 literals when requested",
    );

    const i105Transactions = await client.accountTransactions(senderAccountId).list({
      limit: 5,
    });
    const listAuthority = (i105Transactions?.items ?? []).find(
      (entry) => typeof entry?.authority === "string",
    );
    assert.ok(
      listAuthority,
      "account transaction list should include an entry with an authority literal",
    );
    assert.equal(
      listAuthority.authority,
      AUTHORITY_ACCOUNT_ID,
      "account transaction list should emit canonical authority literals",
    );

    const i105TransactionQuery = await client.accountTransactions(senderAccountId).list({
      filter: field("authority").eq(AUTHORITY_ACCOUNT_ID),
      limit: 5,
    });
    const queryAuthority = (i105TransactionQuery?.items ?? []).find(
      (entry) => typeof entry?.authority === "string",
    );
    assert.ok(
      queryAuthority,
      "account transaction query should include an entry with an authority literal",
    );
    assert.equal(
      queryAuthority.authority,
      AUTHORITY_ACCOUNT_ID,
      "account transaction query should emit canonical authority literals",
    );

    const i105TransactionIteratorFound = await iteratorIncludes(
      client.accountTransactions(senderAccountId).iterate({
        limit: 5,
      }),
      (entry) => entry?.authority === AUTHORITY_ACCOUNT_ID,
    );
    assert.ok(
      i105TransactionIteratorFound,
      "account transaction iterator should emit i105 authority literals",
    );

    const i105TransactionQueryIteratorFound = await iteratorIncludes(
      client.accountTransactions(senderAccountId).iterate({
        sort: "-timestamp_ms,entrypoint_hash",
        limit: 5,
      }),
      (entry) => entry?.authority === AUTHORITY_ACCOUNT_ID,
    );
    assert.ok(
      i105TransactionQueryIteratorFound,
      "account transaction query iterator should emit i105 authority literals",
    );
  },
);

test(
  "repo agreement list and query endpoints return typed payloads (optional)",
  {
    timeout: 60_000,
  },
  async (t) => {
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
    });

    let listPage;
    try {
      listPage = await client.repoAgreements.list({ limit: 5, includeTotal: true });
    } catch (error) {
      if (isUnexpectedNotFoundError(error)) {
        t.diagnostic(
          `repo agreement list endpoint unavailable: ${
            error instanceof Error ? error.message : String(error)
          }`,
        );
        return;
      }
      throw error;
    }

    assertNonNegativeInteger(listPage.total, "repo agreement list total");
    assert.ok(Array.isArray(listPage.items), "repo agreement list must expose items array");

    if (listPage.items.length === 0) {
      t.diagnostic("Torii repo agreement list returned zero entries; skipping field assertions");
      return;
    }

    const agreement = listPage.items[0];
    assertRepoAgreementSnapshot(agreement, "repo agreement list entry");

    const repoFilter = field("id").eq(agreement.id);
    let queryPage;
    try {
      queryPage = await client.repoAgreements.list({ filter: repoFilter, limit: 1, includeTotal: true });
    } catch (error) {
      if (isUnexpectedNotFoundError(error)) {
        t.diagnostic(
          `repo agreement query endpoint unavailable: ${
            error instanceof Error ? error.message : String(error)
          }`,
        );
        return;
      }
      throw error;
    }

    assertNonNegativeInteger(queryPage.total, "repo agreement query total");
    assert.ok(Array.isArray(queryPage.items), "repo agreement query must expose items array");
    assert.ok(
      queryPage.items.some((entry) => entry?.id === agreement.id),
      "repo agreement query should include the filtered agreement",
    );

    const iteratorListFound = await iteratorIncludes(
      client.repoAgreements.iterate({ filter: repoFilter, limit: 5 }),
      (entry) => entry?.id === agreement.id,
    );
    assert.ok(iteratorListFound, "repo agreement iterator should surface the filtered agreement");

    const iteratorQueryFound = await iteratorIncludes(
      client.repoAgreements.iterate({ filter: repoFilter.toString(), limit: 5 }),
      (entry) => entry?.id === agreement.id,
    );
    assert.ok(
      iteratorQueryFound,
      "repo agreement query iterator should surface the filtered agreement",
    );
  },
);

test(
  "attachment upload/list/fetch/delete lifecycle (optional)",
  {
    timeout: 60_000,
  },
  async (t) => {
    if (!MUTATION_ENABLED) {
      t.diagnostic("set IROHA_TORII_INTEGRATION_MUTATE=1 to enable attachment coverage");
      return;
    }
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
      localSigningContext: new LocalSigningContext(NETWORK_ID, 753),
    });
    const canonicalAuth = { accountId: AUTHORITY_ACCOUNT_ID, privateKey: Buffer.from(PRIVATE_KEY_HEX, "hex") };
    const attachmentPayload = Buffer.from(
      `iroha-js-attachment-${Date.now().toString(16)}-${Math.random().toString(16).slice(2)}`,
      "utf8",
    );

    let uploaded;
    try {
      uploaded = await client.uploadAttachment(attachmentPayload, {
        contentType: "text/plain",
        canonicalAuth,
      });
    } catch (error) {
      if (isAttachmentEndpointUnavailable(error)) {
        t.diagnostic(
          `attachment upload endpoint unavailable on target node: ${
            error instanceof Error ? error.message : String(error)
          }`,
        );
        return;
      }
      throw error;
    }
    assertAttachmentMetadata(uploaded, "attachment upload metadata");
    let attachmentList;
    try {
      attachmentList = await client.listAttachments({ canonicalAuth });
    } catch (error) {
      if (isAttachmentEndpointUnavailable(error)) {
        t.diagnostic(
          `attachment list endpoint unavailable on target node: ${
            error instanceof Error ? error.message : String(error)
          }`,
        );
        return;
      }
      throw error;
    }
    assert.ok(Array.isArray(attachmentList), "listAttachments must return an array");

    const listedEntry = attachmentList.find((entry) => entry?.id === uploaded.id);
    if (listedEntry) {
      assertAttachmentMetadata(listedEntry, "listed attachment metadata");
    } else {
      t.diagnostic("uploaded attachment not yet visible in list; continuing with direct fetch");
    }

    let fetched;
    try {
      fetched = await client.getAttachment(uploaded.id, { canonicalAuth });
    } catch (error) {
      if (isAttachmentEndpointUnavailable(error)) {
        t.diagnostic(
          `attachment fetch endpoint unavailable on target node: ${
            error instanceof Error ? error.message : String(error)
          }`,
        );
        return;
      }
      throw error;
    }
    assert.ok(Buffer.isBuffer(fetched.data), "getAttachment should return a Buffer");
    assert.equal(
      fetched.contentType,
      uploaded.contentType,
      "getAttachment should preserve content type metadata",
    );
    assert.equal(
      fetched.data.toString("utf8"),
      attachmentPayload.toString("utf8"),
      "attachment payload should round-trip exactly",
    );
    try {
      await client.deleteAttachment(uploaded.id, { canonicalAuth });
    } catch (error) {
      if (isAttachmentEndpointUnavailable(error)) {
        t.diagnostic(
          `attachment delete endpoint unavailable on target node: ${
            error instanceof Error ? error.message : String(error)
          }`,
        );
        return;
      }
      throw error;
    }

    const deleted = await waitForAttachmentDeletion(client, uploaded.id, canonicalAuth);
    if (!deleted) {
      t.diagnostic(
        `attachment ${uploaded.id} still retrievable after delete; retention policy may delay cleanup`,
      );
    }
  },
);

test(
  "trigger list, lookup, and query endpoints return typed payloads (optional)",
  {
    timeout: 60_000,
  },
  async (t) => {
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
    });

    let listPage;
    try {
      listPage = await client.listTriggers({ limit: 5 });
    } catch (error) {
      if (shouldSkipTriggerEndpoints(error)) {
        t.diagnostic(
          `trigger list endpoint unavailable: ${
            error instanceof Error ? error.message : String(error)
          }`,
        );
        return;
      }
      throw error;
    }

    assertNonNegativeInteger(listPage.total, "trigger list total");
    assert.ok(Array.isArray(listPage.items), "trigger list must expose items array");

    if (listPage.items.length === 0) {
      let emptyQuery;
      try {
        emptyQuery = await client.queryTriggers({ limit: 1 });
      } catch (error) {
        if (shouldSkipTriggerEndpoints(error)) {
          t.diagnostic(
            `trigger query endpoint unavailable: ${
              error instanceof Error ? error.message : String(error)
            }`,
          );
          return;
        }
        throw error;
      }
      assertNonNegativeInteger(emptyQuery.total, "trigger query total");
      assert.ok(Array.isArray(emptyQuery.items), "trigger query must expose items array");
      t.diagnostic("trigger list returned zero entries; skipping lookup assertions");
      return;
    }

    const example = listPage.items[0];
    assertTriggerRecord(example, "trigger list entry");

    let lookedUp;
    try {
      lookedUp = await client.getTrigger(example.id);
    } catch (error) {
      if (shouldSkipTriggerEndpoints(error)) {
        t.diagnostic(
          `trigger lookup endpoint unavailable: ${
            error instanceof Error ? error.message : String(error)
          }`,
        );
        return;
      }
      throw error;
    }
    if (!lookedUp) {
      t.diagnostic(`trigger ${example.id} disappeared before lookup finished`);
      return;
    }
    assertTriggerRecord(lookedUp, "trigger lookup response");

    let queryPage;
    try {
      queryPage = await client.queryTriggers({
        filter: field("id").eq(example.id).toJSON(),
        limit: 1,
      });
    } catch (error) {
      if (shouldSkipTriggerEndpoints(error)) {
        t.diagnostic(
          `trigger query endpoint unavailable: ${
            error instanceof Error ? error.message : String(error)
          }`,
        );
        return;
      }
      throw error;
    }

    assertNonNegativeInteger(queryPage.total, "trigger query total");
    assert.ok(Array.isArray(queryPage.items), "trigger query must expose items array");
    assert.ok(
      queryPage.items.some((entry) => entry?.id === example.id),
      "trigger query should include the filtered trigger id",
    );
  },
);

test(
  "register trigger lifecycle via Torii (optional)",
  {
    timeout: 90_000,
  },
  async (t) => {
    if (!MUTATION_ENABLED) {
      t.diagnostic("set IROHA_TORII_INTEGRATION_MUTATE=1 to enable mutation coverage");
      return;
    }
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
    });
    const triggerId = randomTriggerId();
    const namespace = "apps";
    const assetId = composeAssetId(INTEGRATION_ASSET_DEFINITION_IDS[0], AUTHORITY_ACCOUNT_ID);
    const action = buildTimeTriggerAction({
      authority: AUTHORITY_ACCOUNT_ID,
      instructions: [
        buildMintAssetInstruction({
          assetId,
          quantity: "1",
        }),
      ],
      startTimestampMs: Date.now() + 5_000,
      periodMs: 60_000,
      repeats: 1,
      metadata: { label: "js-integration" },
    });
    const metadata = {
      suite: "js-integration",
      intent: "trigger-lifecycle",
      timestamp: Date.now(),
    };

    let created = false;
    try {
      const draft = await client.registerTriggerTyped({
        id: triggerId,
        namespace,
        action,
        metadata,
      });
      created = true;
      assert.ok(draft);
      assert.equal(draft.trigger_id, triggerId);
      assert.ok(
        Array.isArray(draft.tx_instructions),
        "trigger registration should surface Torii tx instructions",
      );

      const record = await client.getTrigger(triggerId);
      assert.ok(record, "trigger lookup should return a payload for the newly registered id");
      assertTriggerRecord(record, "registered trigger lookup");
      assert.equal(record.id, triggerId);
      assert.equal(record.metadata.intent, metadata.intent);

      const page = await client.queryTriggers({
        filter: field("id").eq(triggerId).toJSON(),
        limit: 1,
      });
      assertNonNegativeInteger(page.total, "trigger query total after registration");
      assert.ok(Array.isArray(page.items), "trigger query must expose items array");
      assert.ok(
        page.items.some((entry) => entry?.id === triggerId),
        "trigger query should return the newly registered trigger",
      );
    } catch (error) {
      if (shouldSkipTriggerEndpoints(error)) {
        t.diagnostic(
          `trigger mutation endpoints unavailable: ${
            error instanceof Error ? error.message : String(error)
          }`,
        );
        return;
      }
      throw error;
    } finally {
      if (created) {
        try {
          await client.deleteTrigger(triggerId);
        } catch (cleanupError) {
          const message =
            cleanupError instanceof Error ? cleanupError.message : String(cleanupError);
          t.diagnostic(`failed to delete trigger ${triggerId} during cleanup: ${message}`);
        }
      }
    }
  },
);

test(
  "pipeline block streaming emits events (optional)",
  {
    timeout: 90_000,
  },
  async (t) => {
    if (!STREAM_ENABLED) {
      t.diagnostic(
        "set IROHA_TORII_INTEGRATION_STREAM_ENABLED=1 to exercise event-stream coverage",
      );
      return;
    }
    if (!MUTATION_ENABLED) {
      t.diagnostic("set IROHA_TORII_INTEGRATION_MUTATE=1 to enable mutation coverage");
      return;
    }
    if (!PRIVATE_KEY_HEX) {
      t.diagnostic("IROHA_TORII_INTEGRATION_PRIVATE_KEY_HEX is required for mutation coverage");
      return;
    }

    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
    });
    const privateKey = decodePrivateKeyHex(PRIVATE_KEY_HEX);
    const domainId = randomDomainId();
    const controller = new AbortController();

    const blockEventPromise = waitForPipelineBlockEvent(client, controller.signal);
    const { signedTransaction, hash } = buildRegisterDomainTransaction({
      networkId: NETWORK_ID,
      authority: AUTHORITY_ACCOUNT_ID,
      domainId,
      metadata: {
        suite: "js-integration",
        step: "event-stream",
        timestamp: Date.now(),
      },
      privateKey,
    });
    const statusPromise = client.submitTransactionAndWait(signedTransaction, {
      hashHex: hash.toString("hex"),
      intervalMs: 1_000,
      timeoutMs: 30_000,
    });

    let blockEvent;
    try {
      blockEvent = await withTimeout(
        blockEventPromise,
        45_000,
        "timed out waiting for a pipeline block event",
      );
    } finally {
      controller.abort();
    }

    const status = await statusPromise;
    assertSuccessfulStatus(status, domainId);
    assertPipelineBlockEvent(blockEvent);
  },
);

test(
  "sumeragi status streaming emits consensus snapshots (optional)",
  {
    timeout: 90_000,
  },
  async (t) => {
    if (!STREAM_ENABLED) {
      t.diagnostic(
        "set IROHA_TORII_INTEGRATION_STREAM_ENABLED=1 to exercise stream coverage",
      );
      return;
    }
    if (!MUTATION_ENABLED) {
      t.diagnostic("set IROHA_TORII_INTEGRATION_MUTATE=1 to enable mutation coverage");
      return;
    }
    if (!PRIVATE_KEY_HEX) {
      t.diagnostic("IROHA_TORII_INTEGRATION_PRIVATE_KEY_HEX is required for mutation coverage");
      return;
    }
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
    });
    const privateKey = decodePrivateKeyHex(PRIVATE_KEY_HEX);
    const controller = new AbortController();
    const domainId = randomDomainId();
    const streamPromise = waitForSumeragiStatusEvent(client, controller.signal);
    const { signedTransaction, hash } = buildRegisterDomainTransaction({
      networkId: NETWORK_ID,
      authority: AUTHORITY_ACCOUNT_ID,
      domainId,
      metadata: {
        suite: "js-integration",
        step: "sumeragi-stream",
        timestamp: Date.now(),
      },
      privateKey,
    });
    const statusPromise = client.submitTransactionAndWait(signedTransaction, {
      hashHex: hash.toString("hex"),
      intervalMs: 1_000,
      timeoutMs: 30_000,
    });

    let event;
    try {
      event = await withTimeout(
        streamPromise,
        45_000,
        "timed out waiting for a Sumeragi status event",
      );
    } finally {
      controller.abort();
      const submissionStatus = await statusPromise;
      assertSuccessfulStatus(submissionStatus, domainId);
    }
    assertSumeragiStatusEvent(event);
  },
);

test(
  "account transaction listings surface recent submissions",
  {
    timeout: 120_000,
  },
  async (t) => {
    if (!MUTATION_ENABLED) {
      t.diagnostic("set IROHA_TORII_INTEGRATION_MUTATE=1 to enable mutation coverage");
      return;
    }
    if (!PRIVATE_KEY_HEX) {
      t.diagnostic("IROHA_TORII_INTEGRATION_PRIVATE_KEY_HEX is required for mutation coverage");
      return;
    }

    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
    });
    const privateKey = decodePrivateKeyHex(PRIVATE_KEY_HEX);
    const domainId = randomDomainId();
    const { signedTransaction, hash } = buildRegisterDomainTransaction({
      networkId: NETWORK_ID,
      authority: AUTHORITY_ACCOUNT_ID,
      domainId,
      metadata: {
        suite: "js-integration",
        step: "account-transactions",
        timestamp: Date.now(),
      },
      privateKey,
    });
    const hashHex = hash.toString("hex");

    const status = await client.submitTransactionAndWait(signedTransaction, {
      hashHex,
      intervalMs: 1_000,
      timeoutMs: 30_000,
    });
    assertSuccessfulStatus(status, domainId);

    const matchesHash = (entry) =>
      !!entry &&
      typeof entry.entrypoint_hash === "string" &&
      entry.entrypoint_hash.toLowerCase() === hashHex;

    const waitForMatch = async (fetchPage, context) => {
      for (let attempt = 0; attempt < 5; attempt += 1) {
        const page = await fetchPage();
        assert.ok(page, `${context} should return a payload`);
        assert.equal(typeof page.total, "number", `${context} should expose total count`);
        assert.ok(page.nextCursor === null || typeof page.nextCursor === "string", `${context} should expose nextCursor`);
        const items = page.items ?? [];
        assert.ok(Array.isArray(items), `${context} should expose an items array`);
        const entry = items.find(matchesHash);
        if (entry) {
          return entry;
        }
        await delay(1_000);
      }
      throw new Error(`${context} did not include transaction ${hashHex}`);
    };

    const listEntry = await waitForMatch(
      () => client.accountTransactions(AUTHORITY_ACCOUNT_ID).list({ limit: 25, includeTotal: true }),
      "accountTransactions.list",
    );
    assert.equal(
      listEntry.entrypoint_hash.toLowerCase(),
      hashHex,
      "account transactions list should echo the entrypoint hash",
    );
    if (listEntry.authority) {
      assert.equal(
        listEntry.authority,
        AUTHORITY_ACCOUNT_ID,
        "account transactions entry should report the authority",
      );
    }
    assert.equal(listEntry.result_ok, true, "account transactions entry should report success");

    const iteratorFound = await iteratorIncludes(
      client.accountTransactions(AUTHORITY_ACCOUNT_ID).iterate({ limit: 5 }),
      matchesHash,
    );
    assert.ok(iteratorFound, "account transaction iterator should surface the submission");

    const queryEntry = await waitForMatch(
      () =>
        client.accountTransactions(AUTHORITY_ACCOUNT_ID).list({
          filter: field("entrypoint_hash").eq(hashHex),
          limit: 10,
          sort: "-timestamp_ms",
          includeTotal: true,
        }),
      "accountTransactions.list with filter",
    );
    assert.equal(
      queryEntry.entrypoint_hash.toLowerCase(),
      hashHex,
      "account transactions query should echo the entrypoint hash",
    );

    const iteratorQueryFound = await iteratorIncludes(
      client.accountTransactions(AUTHORITY_ACCOUNT_ID).iterate({ sort: "-timestamp_ms", limit: 5 }),
      matchesHash,
    );
    assert.ok(
      iteratorQueryFound,
      "account transaction query iterator should surface the submission",
    );
  },
);

test(
  "verifying key registry endpoints respond (optional)",
  {
    timeout: 60_000,
  },
  async (t) => {
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
    });
    let summaries;
    try {
      summaries = await client.listVerifyingKeys();
    } catch (error) {
      t.diagnostic(
        `verifying key list endpoint unavailable: ${error instanceof Error ? error.message : String(error)}`,
      );
      return;
    }
    assert.ok(Array.isArray(summaries), "verifying key listing must return an array");
    if (summaries.length === 0) {
      t.diagnostic("verifying key registry returned no entries; skipping detail coverage");
      return;
    }
    const firstSummary = summaries[0];
    assertVerifyingKeyListEntry(firstSummary, "verifying key summary[0]");
    const entryWithRecord = firstSummary.record
      ? firstSummary
      : summaries.find((entry) => entry && entry.record);
    if (!entryWithRecord) {
      t.diagnostic("verifying key list did not include metadata payloads; skipping detail coverage");
      return;
    }
    const targetId = entryWithRecord.id;
    let detail;
    try {
      detail = await client.getVerifyingKey(targetId.backend, targetId.name);
    } catch (error) {
      t.diagnostic(
        `verifying key detail endpoint unavailable for ${targetId.backend}/${targetId.name}: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
      return;
    }
    assertVerifyingKeyDetail(detail, targetId);
  },
);

test(
  "kaigi relay endpoints respond (optional)",
  {
    timeout: 60_000,
  },
  async (t) => {
    const client = OPERATOR_CLIENT;
    let relayList;
    try {
      relayList = await client.listKaigiRelays();
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      t.diagnostic(`kaigi relay list unavailable on target node: ${message}`);
      return;
    }
    assertKaigiRelaySummaryList(relayList);

    let healthSnapshot;
    try {
      healthSnapshot = await client.getKaigiRelaysHealth();
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      t.diagnostic(`kaigi relay health endpoint unavailable on target node: ${message}`);
      return;
    }
    assertKaigiRelayHealthSnapshot(healthSnapshot);

    if (relayList.items.length === 0) {
      t.diagnostic("kaigi relay list returned no entries; skipping relay detail coverage");
      return;
    }

    const relayId = relayList.items[0].relay_id;
    let relayDetail;
    try {
      relayDetail = await client.getKaigiRelay(relayId);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      t.diagnostic(`kaigi relay detail fetch failed for ${relayId}: ${message}`);
      return;
    }
    if (!relayDetail) {
      t.diagnostic(`kaigi relay detail returned null for ${relayId}`);
      return;
    }
    assertKaigiRelayDetail(relayDetail, relayId);
  },
);

 test(
  "call contract entrypoint via Torii (optional)",
  {
    timeout: 120_000,
  },
  async (t) => {
    if (!MUTATION_ENABLED) {
      t.diagnostic("set IROHA_TORII_INTEGRATION_MUTATE=1 to enable contract call coverage");
      return;
    }
    if (!CONTRACT_CALL_OPTIONS) {
      t.diagnostic(
        "set IROHA_TORII_INTEGRATION_CONTRACT_CALL to a JSON object to exercise contract call coverage",
      );
      return;
    }
    if (!PRIVATE_KEY_HEX) {
      t.diagnostic(
        "IROHA_TORII_INTEGRATION_PRIVATE_KEY_HEX is required for contract call coverage",
      );
      return;
    }

    const contractAddress = (
      CONTRACT_CALL_OPTIONS.contractAddress ??
      CONTRACT_CALL_OPTIONS.contract_address ??
      ""
    ).trim();
    const contractAlias = (
      CONTRACT_CALL_OPTIONS.contractAlias ??
      CONTRACT_CALL_OPTIONS.contract_alias ??
      ""
    ).trim();
    if (!contractAddress && !contractAlias) {
      t.diagnostic(
        "contract call payload must include non-empty `contractAddress`/`contract_address` or `contractAlias`/`contract_alias`",
      );
      return;
    }
    if (contractAddress && contractAlias) {
      t.diagnostic(
        "contract call payload must not set both contractAddress and contractAlias",
      );
      return;
    }

    const authority =
      CONTRACT_CALL_OPTIONS.authority ??
      CONTRACT_CALL_OPTIONS.account ??
      AUTHORITY_ACCOUNT_ID;
    const request = {
      authority,
    };
    if (contractAddress) {
      request.contractAddress = contractAddress;
    } else {
      request.contractAlias = contractAlias;
    }

    const entrypoint =
      CONTRACT_CALL_OPTIONS.entrypoint ?? CONTRACT_CALL_OPTIONS.entryPoint ?? null;
    if (!isNonEmptyString(entrypoint)) {
      t.diagnostic(
        "contract call payload must include non-empty `entrypoint`/`entryPoint`",
      );
      return;
    }
    request.entrypoint = entrypoint;
    if (Object.prototype.hasOwnProperty.call(CONTRACT_CALL_OPTIONS, "payload")) {
      request.payload = CONTRACT_CALL_OPTIONS.payload;
    }
    const feePayment =
      CONTRACT_CALL_OPTIONS.feePayment ?? CONTRACT_CALL_OPTIONS.fee_payment ?? null;
    if (feePayment === null || typeof feePayment !== "object" || Array.isArray(feePayment)) {
      t.diagnostic(
        "contract call payload must include exact quoted `feePayment`/`fee_payment` intent",
      );
      return;
    }
    request.feePayment = feePayment;
    assert.ok(isPlainObject(CONTRACT_CALL_OPTIONS.draftIntent),
      "contract coverage requires caller-trusted executable, metadata, and resolved target draftIntent");
    request.draftIntent = CONTRACT_CALL_OPTIONS.draftIntent;
    for (const key of ["metadata", "creationTimeMs", "transactionTtlMs"]) {
      if (Object.hasOwn(CONTRACT_CALL_OPTIONS, key)) request[key] = CONTRACT_CALL_OPTIONS[key];
    }

    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
      localSigningContext: new LocalSigningContext(NETWORK_ID, 753),
      canonicalRequestAuth: { accountId: authority, privateKey: decodePrivateKeyHex(PRIVATE_KEY_HEX) },
    });

    let response;
    try {
      response = await client.prepareContractCall(request);
    } catch (error) {
      t.diagnostic(
        `prepareContractCall failed: ${error instanceof Error ? error.message : String(error)}`,
      );
      throw error;
    }
    assert.ok(response, "contract call should return a response payload");
    if (contractAddress) {
      assert.equal(
        response.contract_address,
        contractAddress,
        "contract call response must echo contract address",
      );
    }
    assert.equal(response.submitted, false);
    assert.equal(response.tx_hash_hex, null);
    assert.ok(response.transaction_payload_b64);
    assert.ok(response.signing_message_b64);
    assertHexString(response.code_hash_hex, "contract call response.code_hash_hex");
    assertHexString(response.abi_hash_hex, "contract call response.abi_hash_hex");
  },
);

test(
  "pipeline recovery sidecar exposes DAG + tx metadata (optional)",
  {
    timeout: 60_000,
  },
  async (t) => {
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
    });
    const blocksPage = await client.explorerBlocks.list({ limit: 5 });
    const candidateHeights = (blocksPage?.items ?? [])
      .map((entry) => entry?.height)
      .filter(
        (value) =>
          (Number.isFinite(value) && value >= 0) ||
          (typeof value === "bigint" && value >= 0n),
      );
    if (candidateHeights.length === 0) {
      t.diagnostic("no block heights available for pipeline recovery sampling");
      return;
    }

    const attemptedHeights = [];
    for (const height of candidateHeights) {
      attemptedHeights.push(height);
      const recovery = await OPERATOR_CLIENT.getPipelineRecoveryTyped(height);
      if (!recovery) {
        continue;
      }
      assert.ok(
        typeof recovery.format === "string" && recovery.format.length > 0,
        "pipeline recovery format must be a non-empty string",
      );
      assertNonNegativeInteger(recovery.height, "pipeline recovery height");
      assert.ok(
        recovery.dag && typeof recovery.dag === "object",
        "pipeline recovery must include a dag payload",
      );
      assertHexString(recovery.dag.fingerprintHex, "pipeline recovery dag fingerprint");
      assertNonNegativeInteger(recovery.dag.keyCount, "pipeline recovery dag keyCount");
      assert.ok(Array.isArray(recovery.txs), "pipeline recovery txs must be an array");
      recovery.txs.forEach((tx, index) => {
        assertHexString(tx.hashHex, `pipeline recovery txs[${index}].hashHex`);
        assert.ok(Array.isArray(tx.reads), `pipeline recovery txs[${index}].reads must be an array`);
        tx.reads.forEach((key, keyIndex) => {
          assert.ok(
            isNonEmptyString(key),
            `pipeline recovery txs[${index}].reads[${keyIndex}] must be a non-empty string`,
          );
        });
        assert.ok(Array.isArray(tx.writes), `pipeline recovery txs[${index}].writes must be an array`);
        tx.writes.forEach((key, keyIndex) => {
          assert.ok(
            isNonEmptyString(key),
            `pipeline recovery txs[${index}].writes[${keyIndex}] must be a non-empty string`,
          );
        });
      });
      if (recovery.txs.length === 0) {
        t.diagnostic(`pipeline recovery sidecar for height ${height} returned zero transactions`);
      }
      return;
    }
    t.diagnostic(
      `pipeline recovery endpoint did not expose artefacts for sampled heights: ${attemptedHeights.join(
        ", ",
      )}`,
    );
  },
);

test(
  "SoraFS registry endpoints respond (optional)",
  {
    timeout: 90_000,
  },
  async (t) => {
    if (!SORAFS_ENABLED) {
      t.diagnostic(
        "set IROHA_TORII_INTEGRATION_SORAFS_ENABLED=1 to exercise SoraFS registry/storage coverage",
      );
      return;
    }
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
      localSigningContext: new LocalSigningContext(NETWORK_ID, 753),
    });
    const canonicalAuth = {
      accountId: AUTHORITY_ACCOUNT_ID,
      privateKey: PRIVATE_KEY_HEX,
    };
    const pinList = await client.listSorafsPinManifests({ limit: 5 });
    assert.ok(Array.isArray(pinList.manifests), "pin manifest list must include manifests array");
    assert.ok(
      Number.isInteger(pinList.finalized_cursor.height) && pinList.finalized_cursor.height > 0,
      "pin manifest list must include a positive finalized height",
    );
    assert.equal(pinList.finalized_cursor.block_hash.length, 32);
    assert.ok(Number.isInteger(pinList.charged_usage.manifest_count));
    assert.ok(Number.isInteger(pinList.charged_usage.content_bytes));

    if (pinList.manifests.length > 0) {
      const [manifest] = pinList.manifests;
      const manifestDigestHex = Buffer.from(manifest.digest).toString("hex");
      assertHexString(manifestDigestHex, "SoraFS manifest digest");
      assert.ok(
        manifest.approved_epoch === null || Number.isInteger(manifest.approved_epoch),
        "pin summaries must expose an explicit nullable approval epoch",
      );
      assert.equal("alias" in manifest, false, "list summaries must omit alias proofs");
      assert.equal("metadata" in manifest, false, "list summaries must omit metadata");
      assert.equal("lineage" in manifest, false, "list summaries must omit lineage expansion");
      const iteratorHit = await iteratorIncludes(
        client.iterateSorafsPinManifests({ pageSize: 1, maxItems: 10 }),
        (entry) => Buffer.from(entry.digest).toString("hex") === manifestDigestHex,
      );
      assert.ok(iteratorHit, "pin manifest iterator should surface the sampled manifest");
    } else {
      t.diagnostic("SoraFS pin registry returned no manifests");
    }

    const aliasList = await client.listSorafsAliases({ limit: 5, canonicalAuth });
    assert.ok(Array.isArray(aliasList.aliases), "alias list must include aliases array");
    if (aliasList.aliases.length > 0) {
      const aliasRecord = aliasList.aliases[0];
      assert.ok(aliasRecord.alias.length > 0, "alias entries must expose alias labels");
      assertHexString(aliasRecord.manifest_digest_hex, "alias manifest digest");
      const aliasIteratorHit = await iteratorIncludes(
        client.iterateSorafsAliases({ pageSize: 1, maxItems: 10, canonicalAuth }),
        (entry) =>
          entry?.alias === aliasRecord.alias &&
          entry?.manifest_digest_hex === aliasRecord.manifest_digest_hex,
      );
      assert.ok(aliasIteratorHit, "alias iterator should surface the sampled alias");
    } else {
      t.diagnostic("SoraFS alias list is empty on target node");
    }

    const replicationList = await client.listSorafsReplicationOrders({ limit: 5, canonicalAuth });
    assert.ok(
      Array.isArray(replicationList.replication_orders),
      "replication order list must expose replication_orders",
    );
    if (replicationList.replication_orders.length > 0) {
      const order = replicationList.replication_orders[0];
      assertHexString(order.order_id_hex, "replication order id");
      assert.ok(
        Array.isArray(order.provider_completions),
        "replication order entries must include provider_completions array",
      );
      const replicationIteratorHit = await iteratorIncludes(
        client.iterateSorafsReplicationOrders({ pageSize: 1, maxItems: 10, canonicalAuth }),
        (entry) => entry?.order_id_hex === order.order_id_hex,
      );
      assert.ok(
        replicationIteratorHit,
        "replication iterator should surface the sampled order id",
      );
    } else {
      t.diagnostic("SoraFS replication order list is empty on target node");
    }

    t.diagnostic(
      "SoraFS storage state is an operator-only local diagnostic and is not exercised by the public integration client",
    );
  },
);

test(
  "SoraFS PoR status/export endpoints respond (optional)",
  {
    timeout: 90_000,
  },
  async (t) => {
    if (!SORAFS_ENABLED) {
      t.diagnostic("set IROHA_TORII_INTEGRATION_SORAFS_ENABLED=1 to exercise SoraFS PoR coverage");
      return;
    }
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
    });
    const statusBuffer = await client.getSorafsPorStatus();
    assert.ok(Buffer.isBuffer(statusBuffer), "PoR status endpoint must return a Buffer");

    const exportBuffer = await client.exportSorafsPorStatus();
    assert.ok(Buffer.isBuffer(exportBuffer), "PoR export endpoint must return a Buffer");
  },
);

test(
  "SoraFS PoR weekly report fetch (optional)",
  {
    timeout: 90_000,
  },
  async (t) => {
    if (!SORAFS_ENABLED) {
      t.diagnostic("set IROHA_TORII_INTEGRATION_SORAFS_ENABLED=1 to exercise SoraFS PoR coverage");
      return;
    }
    if (!SORAFS_POR_WEEK) {
      throw new Error(
        "set IROHA_TORII_INTEGRATION_SORAFS_POR_WEEK (e.g. 2026-W05) to enable PoR weekly report coverage",
      );
    }
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
    });
    const reportBuffer = await client.getSorafsPorWeeklyReport(SORAFS_POR_WEEK);
    assert.ok(Buffer.isBuffer(reportBuffer), "PoR weekly report must return a Buffer");
  },
);

test(
  "UAID portfolio endpoint responds (optional)",
  {
    timeout: 60_000,
  },
  async (t) => {
    if (!UAID_LITERAL) {
      t.diagnostic(
        "set IROHA_TORII_INTEGRATION_UAID=uaid:<64-lowercase-hex> to exercise UAID portfolio coverage",
      );
      return;
    }
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
    });
    const portfolio = await client.getUaidPortfolio(UAID_LITERAL);
    assertUaidPortfolioSnapshot(portfolio, UAID_LITERAL);
  },
);

test(
  "UAID bindings endpoint responds (optional)",
  {
    timeout: 60_000,
  },
  async (t) => {
    if (!UAID_LITERAL) {
      t.diagnostic(
        "set IROHA_TORII_INTEGRATION_UAID=uaid:<64-lowercase-hex> to exercise UAID bindings coverage",
      );
      return;
    }
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
    });
    const bindings = await client.getUaidBindings(UAID_LITERAL);
    assertUaidBindingsSnapshot(bindings, UAID_LITERAL);
  },
);

test(
  "UAID manifests endpoint responds (optional)",
  {
    timeout: 60_000,
  },
  async (t) => {
    if (!UAID_LITERAL) {
      t.diagnostic(
        "set IROHA_TORII_INTEGRATION_UAID=uaid:<64-lowercase-hex> to exercise UAID manifest coverage",
      );
      return;
    }
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
    });
    const manifestOptions =
      UAID_DATASPACE_ID === null ? undefined : { filter: `dataspace_id = ${UAID_DATASPACE_ID}` };
    const manifests = await client.uaidManifests(UAID_LITERAL).list(manifestOptions);
    assertUaidManifestsSnapshot(manifests, UAID_LITERAL);
    assert.notEqual(
      manifests.items.length,
      0,
      "UAID manifests endpoint must return the qualification manifest for the supplied UAID",
    );
  },
);

test(
  "Sora Name Service policy endpoint responds (optional)",
  {
    timeout: 60_000,
  },
  async (t) => {
    if (SNS_SUFFIX_ID === null) {
      t.diagnostic(
        "set IROHA_TORII_INTEGRATION_SNS_SUFFIX=<u16> to exercise SNS policy coverage",
      );
      return;
    }
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
    });
    let policy;
    try {
      policy = await client.getSnsPolicy(SNS_SUFFIX_ID);
    } catch (error) {
      t.diagnostic(
        `SNS policy endpoint unavailable: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
      return;
    }
    assertSnsPolicySnapshot(policy, SNS_SUFFIX_ID);
  },
);

test(
  "Sora Name Service registration endpoint responds (optional)",
  {
    timeout: 60_000,
  },
  async (t) => {
    const selector = normalizeIntegrationString(SNS_SELECTOR);
    if (!selector) {
      t.diagnostic(
        "set IROHA_TORII_INTEGRATION_SNS_SELECTOR=<label.suffix> to exercise SNS registration coverage",
      );
      return;
    }
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
    });
    let registration;
    try {
      registration = await client.getSnsRegistration(selector);
    } catch (error) {
      t.diagnostic(
        `SNS registration endpoint unavailable: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
      return;
    }
    assertSnsNameRecord(registration, selector);
  },
);

test(
  "Space Directory manifest publish (optional)",
  {
    timeout: 120_000,
  },
  async (t) => {
    if (!SPACE_DIRECTORY_ENABLED) {
      t.diagnostic(
        "set IROHA_TORII_INTEGRATION_SPACE_DIRECTORY_ENABLED=1 with a manifest path to exercise Space Directory publish coverage",
      );
      return;
    }
    if (!MUTATION_ENABLED) {
      throw new Error("IROHA_TORII_INTEGRATION_MUTATE=1 is required when Space Directory coverage is enabled");
    }
    if (!PRIVATE_KEY_HEX) {
      throw new Error(
        "set IROHA_TORII_INTEGRATION_PRIVATE_KEY_HEX=<hex> to sign Space Directory manifests",
      );
    }
    const manifestFixture = loadSpaceDirectoryManifestFixture();
    const manifestPayload = canonicalizeSpaceDirectoryManifest(manifestFixture.manifest);
    const uaidLiteral = typeof manifestPayload.uaid === "string" ? manifestPayload.uaid.trim() : "";
    if (!uaidLiteral) {
      throw new Error(
        `Space Directory manifest fixture ${manifestFixture.path} is missing a uaid literal`,
      );
    }
    const dataspaceId = coerceNonNegativeInteger(manifestPayload.dataspace);
    if (dataspaceId === null) {
      throw new Error(
        `Space Directory manifest fixture ${manifestFixture.path} is missing a dataspace id`,
      );
    }
    const publishReason = `js-integration publish ${new Date().toISOString()}`;
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
    });
    try {
      const publishResult = await client.publishSpaceDirectoryManifest({
        authority: AUTHORITY_ACCOUNT_ID,
        manifest: manifestPayload,
        reason: publishReason,
      }, { canonicalAuth: { accountId: AUTHORITY_ACCOUNT_ID, privateKey: PRIVATE_KEY_HEX } });
      assert.ok(
        publishResult === null || typeof publishResult === "object",
        "publishSpaceDirectoryManifest should return null or a JSON body",
      );
      const entriesCount = Array.isArray(manifestPayload.entries)
        ? manifestPayload.entries.length
        : 0;
      const activationEpoch = coerceNonNegativeInteger(
        manifestPayload.activation_epoch ?? manifestPayload.activationEpoch,
      );
      const expiryEpoch = coerceNonNegativeInteger(
        manifestPayload.expiry_epoch ?? manifestPayload.expiryEpoch,
      );
      const { record: publishedRecord } = await waitForUaidManifestRecord(
        client,
        uaidLiteral,
        dataspaceId,
        {
          predicate: (record) => record.status === "Pending" || record.status === "Active",
          attempts: 10,
          delayMs: 1_000,
        },
      );
      assert.equal(
        publishedRecord.manifest.uaid,
        uaidLiteral,
        "published manifest should echo the UAID literal from the fixture",
      );
      assert.equal(
        publishedRecord.manifest.dataspace,
        dataspaceId,
        "published manifest should report the dataspace id from the fixture",
      );
      if (activationEpoch !== null) {
        assert.equal(
          publishedRecord.manifest.activation_epoch,
          activationEpoch,
          "published manifest should retain the activation epoch from the fixture",
        );
      }
      if (expiryEpoch !== null) {
        assert.equal(
          publishedRecord.manifest.expiry_epoch,
          expiryEpoch,
          "published manifest should retain the expiry epoch from the fixture",
        );
      }
      assert.equal(
        publishedRecord.manifest.entries.length,
        entriesCount,
        "published manifest entries count should match the fixture entries",
      );
      assert.equal(
        publishedRecord.manifest.version,
        manifestPayload.version,
        "published manifest version should match the fixture",
      );
    } catch (error) {
      t.diagnostic(
        `Space Directory manifest publish failed for fixture ${manifestFixture.path}: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
      throw error;
    }
  },
);

test(
  "Space Directory manifest revoke (optional)",
  {
    timeout: 120_000,
  },
  async (t) => {
    if (!SPACE_DIRECTORY_ENABLED) {
      t.diagnostic(
        "set IROHA_TORII_INTEGRATION_SPACE_DIRECTORY_ENABLED=1 with revoke inputs to exercise Space Directory revoke coverage",
      );
      return;
    }
    if (!MUTATION_ENABLED) {
      throw new Error("IROHA_TORII_INTEGRATION_MUTATE=1 is required when Space Directory coverage is enabled");
    }
    if (!PRIVATE_KEY_HEX) {
      throw new Error(
        "set IROHA_TORII_INTEGRATION_PRIVATE_KEY_HEX=<hex> to sign Space Directory requests",
      );
    }
    const manifestFixture = loadSpaceDirectoryManifestFixture();
    const manifestPayload = canonicalizeSpaceDirectoryManifest(manifestFixture.manifest);
    const uaidLiteral = typeof manifestPayload.uaid === "string" ? manifestPayload.uaid.trim() : "";
    if (!uaidLiteral) {
      throw new Error(
        `Space Directory manifest fixture ${manifestFixture.path} is missing a uaid literal`,
      );
    }
    const dataspaceId = coerceNonNegativeInteger(manifestPayload.dataspace);
    if (dataspaceId === null) {
      throw new Error(
        `Space Directory manifest fixture ${manifestFixture.path} must include a numeric dataspace id`,
      );
    }
    const fixtureEpoch =
      coerceNonNegativeInteger(manifestPayload.expiry_epoch ?? manifestPayload.expiryEpoch) ??
      coerceNonNegativeInteger(manifestPayload.activation_epoch ?? manifestPayload.activationEpoch);
    const revokedEpoch = SPACE_DIRECTORY_REVOKE_EPOCH ?? fixtureEpoch;
    if (revokedEpoch === null) {
      throw new Error(
        "set IROHA_TORII_INTEGRATION_SPACE_DIRECTORY_REVOKE_EPOCH=<epoch> or include activation/expiry epochs in the manifest fixture",
      );
    }
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
      localSigningContext: new LocalSigningContext(NETWORK_ID, 753),
    });
    try {
      const revokeReason = `js-integration revoke ${new Date().toISOString()}`;
      const revokeResult = await client.revokeSpaceDirectoryManifest({
        authority: AUTHORITY_ACCOUNT_ID,
        uaid: uaidLiteral,
        dataspace: dataspaceId,
        revokedEpoch,
        reason: revokeReason,
      }, { canonicalAuth: { accountId: AUTHORITY_ACCOUNT_ID, privateKey: PRIVATE_KEY_HEX } });
      assert.ok(
        revokeResult === null || typeof revokeResult === "object",
        "revokeSpaceDirectoryManifest should return null or a JSON body",
      );
      const { record: revokedRecord } = await waitForUaidManifestRecord(
        client,
        uaidLiteral,
        dataspaceId,
        {
          predicate: (record) =>
            Boolean(
              record.lifecycle.revocation && record.lifecycle.revocation.epoch === revokedEpoch,
            ),
          attempts: 10,
          delayMs: 1_000,
        },
      );
      const revocation = revokedRecord.lifecycle.revocation;
      assert.ok(revocation, "revoked manifest should expose a revocation lifecycle entry");
      assert.equal(
        revocation.epoch,
        revokedEpoch,
        "revoked manifest lifecycle should echo the requested revocation epoch",
      );
      if (typeof revocation.reason === "string" && revocation.reason.length > 0) {
        assert.ok(
          revocation.reason.includes("js-integration"),
          "revoked manifest reason should mirror the integration request tag",
        );
      }
      assert.equal(
        revokedRecord.manifest.dataspace,
        dataspaceId,
        "revoked manifest should remain bound to the requested dataspace",
      );
      if (revokedRecord.status !== "Revoked") {
        t.diagnostic(
          `Space Directory manifest revocation recorded with status=${revokedRecord.status}`,
        );
      }
    } catch (error) {
      t.diagnostic(
        `Space Directory manifest revoke failed for UAID ${uaidLiteral}: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
      throw error;
    }
  },
);

test(
  "DA ingest submits payload (optional)",
  {
    timeout: 150_000,
  },
  async (t) => {
    if (!DA_ENABLED) {
      t.diagnostic("set IROHA_TORII_INTEGRATION_DA_ENABLED=1 to exercise DA ingest coverage");
      return;
    }
    if (!MUTATION_ENABLED) {
      t.diagnostic("set IROHA_TORII_INTEGRATION_MUTATE=1 to enable DA ingest coverage");
      return;
    }
    if (!PRIVATE_KEY_HEX) {
      t.diagnostic("IROHA_TORII_INTEGRATION_PRIVATE_KEY_HEX is required for DA ingest coverage");
      return;
    }
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
    });
    const payloadBuffer = Buffer.from(
      `js-da-ingest-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`,
      "utf8",
    );
    const metadata = {
      suite: "js-integration",
      step: "da-ingest",
      timestamp: new Date().toISOString(),
    };
    const submission = await client.submitDaBlob({
      networkId: NETWORK_ID,
      owner: AUTHORITY_ACCOUNT_ID,
      payload: payloadBuffer,
      codec: "application/octet-stream",
      metadata,
      privateKeyHex: PRIVATE_KEY_HEX,
    });
    assert.equal(
      typeof submission.status,
      "string",
      "da ingest response should include status string",
    );
    assert.equal(
      typeof submission.duplicate,
      "boolean",
      "da ingest response should include duplicate flag",
    );
    assert.ok(submission.receipt, "da ingest response should provide a receipt");
    assertHexString(
      submission.receipt.storage_ticket_hex,
      "da ingest receipt storage_ticket_hex",
    );
    assertHexString(
      submission.receipt.blob_hash_hex,
      "da ingest receipt blob_hash_hex",
    );
    assertHexString(
      submission.artifacts.clientBlobIdHex,
      "da ingest artifacts clientBlobIdHex",
    );
    assert.equal(
      submission.artifacts.clientBlobIdHex,
      submission.receipt.client_blob_id_hex,
      "ingest artifacts should mirror the receipt digest",
    );

    try {
      const manifest = await waitForDaManifest(
        client,
        submission.receipt.storage_ticket_hex,
        { attempts: 6, intervalMs: 5_000 },
      );
      assert.equal(
        manifest.storage_ticket_hex,
        submission.receipt.storage_ticket_hex,
        "manifest ticket should match ingest receipt",
      );
      assertHexString(manifest.blob_hash_hex, "da manifest blob hash");
      assert.ok(manifest.manifest_bytes.length > 0, "da manifest should return bytes payload");
    } catch (error) {
      t.diagnostic(`da manifest polling failed: ${error instanceof Error ? error.message : error}`);
      throw error;
    }
  },
);

test(
  "DA manifest and gateway fetch (optional)",
  {
    timeout: 120_000,
  },
  async (t) => {
    if (!DA_ENABLED) {
      t.diagnostic("set IROHA_TORII_INTEGRATION_DA_ENABLED=1 to exercise DA gateway coverage");
      return;
    }
    if (!DA_TICKET_HEX) {
      t.diagnostic(
        "set IROHA_TORII_INTEGRATION_DA_TICKET=<hex storage ticket> to enable DA manifest fetch coverage",
      );
      return;
    }
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
    });
    let manifest;
    try {
      manifest = await client.getDaManifest(DA_TICKET_HEX);
    } catch (error) {
      t.diagnostic(
        `da manifest fetch failed for ${DA_TICKET_HEX}: ${
          error instanceof Error ? error.message : error
        }`,
      );
      throw error;
    }
    assert.equal(
      manifest.storage_ticket_hex,
      DA_TICKET_HEX.toUpperCase(),
      "manifest ticket should match requested value",
    );
    assertHexString(manifest.client_blob_id_hex, "da manifest client blob id");
    assertHexString(manifest.chunk_root_hex, "da manifest chunk root");
    if (!Array.isArray(DA_GATEWAY_SPECS) || DA_GATEWAY_SPECS.length === 0) {
      t.diagnostic(
        "set IROHA_TORII_INTEGRATION_DA_GATEWAYS=[...] to exercise gateway fetch coverage",
      );
      return;
    }
    const session = await client.fetchDaPayloadViaGateway({
      manifestBundle: manifest,
      gatewayProviders: DA_GATEWAY_SPECS,
      proofSummary: false,
    });
    assert.ok(session, "da gateway fetch should return a session record");
    assert.equal(
      session.manifest?.storage_ticket_hex ?? null,
      manifest.storage_ticket_hex,
      "gateway session manifest should mirror fetched manifest",
    );
    assert.ok(
      Array.isArray(session.reports),
      "da gateway fetch response must include reports array",
    );
  },
);

test(
  "connect app registry lifecycle (optional)",
  {
    timeout: 120_000,
  },
  async (t) => {
    if (!MUTATION_ENABLED) {
      t.diagnostic("set IROHA_TORII_INTEGRATION_MUTATE=1 to enable connect registry coverage");
      return;
    }
    if (!isPlainObject(CONNECT_APP_CONFIG)) {
      t.diagnostic(
        "set IROHA_TORII_INTEGRATION_CONNECT_APP to a JSON object to exercise the connect registry lifecycle",
      );
      return;
    }
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
    });
    const base = CONNECT_APP_CONFIG ?? {};
    const baseAppId =
      typeof base.appId === "string" && base.appId.trim().length > 0
        ? base.appId.trim()
        : "js-connect-app";
    const suffix = `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`;
    const appId = `${baseAppId}-${suffix}`;
    const namespaces =
      Array.isArray(base.namespaces) && base.namespaces.length > 0
        ? base.namespaces.map((value, index) => {
            if (typeof value !== "string") {
              throw new TypeError(
                `IROHA_TORII_INTEGRATION_CONNECT_APP.namespaces[${index}] must be a string`,
              );
            }
            const trimmed = value.trim();
            if (!trimmed) {
              throw new TypeError(
                `IROHA_TORII_INTEGRATION_CONNECT_APP.namespaces[${index}] must not be empty`,
              );
            }
            return trimmed;
          })
        : ["apps"];
    const metadata = deepMerge(
      {
        suite: "js-integration",
        timestamp: Date.now(),
      },
      isPlainObject(base.metadata) ? base.metadata : {},
    );
    const policy = deepMerge({}, isPlainObject(base.policy) ? base.policy : {});
    const extra = isPlainObject(base.extra) ? base.extra : undefined;
    const record = {
      appId,
      displayName:
        typeof base.displayName === "string" && base.displayName.trim().length > 0
          ? base.displayName
          : `JS Integration ${appId}`,
      description:
        typeof base.description === "string" && base.description.trim().length > 0
          ? base.description
          : "JS integration connect app",
      iconUrl:
        typeof base.iconUrl === "string" && base.iconUrl.trim().length > 0
          ? base.iconUrl
          : undefined,
      namespaces,
      metadata,
      policy,
      extra,
    };
    let createdAppId = null;
    try {
      await client.deleteConnectApp(appId);
      const created = await client.registerConnectApp(record);
      assert.ok(created, "connect app registration should return a payload");
      assert.equal(created.appId, appId);
      createdAppId = appId;

      const fetched = await client.getConnectApp(appId);
      assert.equal(fetched.appId, appId, "getConnectApp should round-trip the newly registered app");

      const page = await client.listConnectApps({ limit: 50 });
      assert.ok(
        page.items.some((entry) => entry.appId === appId),
        "connect registry page should include the newly registered app",
      );

      const iteratorHit = await iteratorIncludes(
        client.iterateConnectApps({ pageSize: 20, maxItems: 200 }),
        (entry) => entry?.appId === appId,
      );
      assert.ok(iteratorHit, "connect registry iterator should yield the test app");

      const removed = await client.deleteConnectApp(appId);
      assert.ok(removed, "connect app deletion should report success");
      createdAppId = null;
    } finally {
      if (createdAppId) {
        try {
          await client.deleteConnectApp(createdAppId);
        } catch (cleanupError) {
          t.diagnostic(
            `failed to delete connect app ${createdAppId}: ${
              cleanupError instanceof Error ? cleanupError.message : String(cleanupError)
            }`,
          );
        }
      }
    }
  },
);

test(
  "connect preview bootstrapper registers Torii sessions (optional)",
  {
    timeout: 120_000,
  },
  async (t) => {
    if (!MUTATION_ENABLED) {
      t.diagnostic("set IROHA_TORII_INTEGRATION_MUTATE=1 to exercise connect preview coverage");
      return;
    }
    if (!isPlainObject(CONNECT_PREVIEW_CONFIG)) {
      t.diagnostic(
        "set IROHA_TORII_INTEGRATION_CONNECT_PREVIEW to a JSON object (e.g. {\"network_id\":\"hash:<genesis>#<checksum>\",\"node\":\"connect.devnet.example\"}) to exercise the preview bootstrapper",
      );
      return;
    }
    if (CONNECT_PREVIEW_CONFIG.register === false) {
      t.diagnostic("connect preview coverage requires register !== false");
      return;
    }

    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
    });
    const previewEnv = CONNECT_PREVIEW_CONFIG ?? {};
    assert.equal(
      Object.hasOwn(previewEnv, "chainId") || Object.hasOwn(previewEnv, "chain_id"),
      false,
      "Connect preview config must use exact network_id, not a human-readable chain label",
    );
    const previewNetworkIdLiteral = normalizeIntegrationString(previewEnv.network_id);
    const previewNetworkId = previewNetworkIdLiteral
      ? NetworkId.parse(previewNetworkIdLiteral)
      : NETWORK_ID;
    const previewNode = normalizeIntegrationString(previewEnv.node);
    const sessionOptionsRaw = isPlainObject(previewEnv.sessionOptions)
      ? previewEnv.sessionOptions
      : null;
    const sanitizedSessionOptions = {};
    const sessionNode = normalizeIntegrationString(sessionOptionsRaw?.node);
    if (sessionNode) {
      sanitizedSessionOptions.node = sessionNode;
    }
    const sessionOptions =
      Object.keys(sanitizedSessionOptions).length === 0 ? undefined : sanitizedSessionOptions;

    let createdSid = null;
    let createdManagementToken = null;
    try {
      const result = await bootstrapConnectPreviewSession(client, {
        networkId: previewNetworkId,
        node: previewNode ?? null,
        nonce: previewEnv.nonce ?? null,
        sessionOptions,
      });
      createdSid = result.preview.sidBase64Url;
      createdManagementToken = result.session?.token_management ?? null;
      assert.ok(
        typeof result.preview.walletUri === "string" &&
          result.preview.walletUri.startsWith("iroha://connect"),
        "preview wallet URI must be canonical",
      );
      assert.ok(result.session, "bootstrap helper should register a session");
      assert.ok(result.tokens, "bootstrap helper should return session tokens");
      assert.equal(
        result.session.sid,
        result.preview.sidBase64Url,
        "session sid must match the preview sid",
      );
      assert.equal(
        result.tokens.wallet,
        result.session.token_wallet,
        "wallet token helper output should match session payload",
      );
      assert.equal(
        result.tokens.app,
        result.session.token_app,
        "app token helper output should match session payload",
      );
      assert.equal(
        result.tokens.management,
        result.session.token_management,
        "management token helper output should match session payload",
      );
      assert.equal(
        result.tokens.relay,
        result.session.token_relay,
        "relay token helper output should match session payload",
      );
      assert.ok(
        typeof result.session.wallet_uri === "string" &&
          result.session.wallet_uri.startsWith("iroha://connect"),
        "connect session wallet URI must be populated",
      );
      assert.ok(
        typeof result.session.app_uri === "string" &&
          result.session.app_uri.includes("connect/app"),
        "connect session app URI must be populated",
      );
      t.diagnostic(
        `bootstrapConnectPreviewSession registered sid=${result.preview.sidBase64Url}`,
      );
    } finally {
      if (createdSid && createdManagementToken) {
        try {
          await client.deleteConnectSession({
            sid: createdSid,
            tokenManagement: createdManagementToken,
          });
        } catch (error) {
          t.diagnostic(
            `failed to delete connect session ${createdSid}: ${error instanceof Error ? error.message : String(error)}`,
          );
        }
      }
    }
  },
);

test(
  "telemetry peer inventory and explorer metrics respond",
  {
    timeout: 60_000,
  },
  async (t) => {
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
    });
    const peers = await client.listTelemetryPeersInfo();
    assert.ok(Array.isArray(peers) && peers.length > 0, "expected telemetry peers list to be non-empty");
    const peer = peers[0];
    assert.equal(typeof peer.url, "string", "telemetry peer must expose url");
    assert.equal(typeof peer.connected, "boolean", "telemetry peer must expose connected flag");
    assert.equal(
      typeof peer.telemetryUnsupported,
      "boolean",
      "telemetry peer must expose telemetryUnsupported flag",
    );
    if (peer.config) {
      assert.equal(typeof peer.config.publicKey, "string", "telemetry peer config must expose publicKey");
    }
    if (peer.location) {
      assert.equal(typeof peer.location.country, "string", "telemetry peer location must expose country");
      assert.equal(typeof peer.location.city, "string", "telemetry peer location must expose city");
    }
    if (peer.connectedPeers) {
      assert.ok(Array.isArray(peer.connectedPeers), "connectedPeers must be an array when present");
    }

    const peerInventory = await OPERATOR_CLIENT.listPeers();
    assert.ok(Array.isArray(peerInventory), "peer inventory payload must be an array");
    const typedPeerInventory = await OPERATOR_CLIENT.listPeersTyped();
    assert.ok(Array.isArray(typedPeerInventory), "typed peer inventory payload must be an array");
    if (typedPeerInventory.length === 0) {
      t.diagnostic("Torii peer inventory returned zero entries");
    } else {
      const typedPeer = typedPeerInventory[0];
      assert.equal(typeof typedPeer.address, "string", "typed peer address must be a string");
      assert.notEqual(typedPeer.address.length, 0, "typed peer address must not be empty");
      assertHexString(typedPeer.public_key_hex, "typed peer public_key_hex");
    }

    const metrics = await client.getExplorerMetrics();
    if (!metrics) {
      t.diagnostic("explorer metrics endpoint disabled on target node");
      return;
    }
    assertNonNegativeInteger(metrics.peers, "explorer metrics peers");
    assertNonNegativeInteger(metrics.domains, "explorer metrics domains");
    assertNonNegativeInteger(metrics.accounts, "explorer metrics accounts");
    assertNonNegativeInteger(metrics.assets, "explorer metrics assets");
    assertNonNegativeInteger(
      metrics.transactionsAccepted,
      "explorer metrics transactionsAccepted",
    );
    assertNonNegativeInteger(
      metrics.transactionsRejected,
      "explorer metrics transactionsRejected",
    );
    assertNonNegativeInteger(metrics.blockHeight, "explorer metrics blockHeight");
    assertNonNegativeInteger(metrics.finalizedBlockHeight, "explorer metrics finalizedBlockHeight");
    if (typeof metrics.blockCreatedAt === "string") {
      assert.notEqual(metrics.blockCreatedAt.length, 0, "blockCreatedAt must not be empty when present");
    }
    if (metrics.averageCommitTimeMs !== null) {
      assert.ok(
        Number.isFinite(metrics.averageCommitTimeMs) && metrics.averageCommitTimeMs >= 0,
        "averageCommitTimeMs must be a non-negative number when present",
      );
    }
    if (metrics.averageBlockTimeMs !== null) {
      assert.ok(
        Number.isFinite(metrics.averageBlockTimeMs) && metrics.averageBlockTimeMs >= 0,
        "averageBlockTimeMs must be a non-negative number when present",
      );
    }
  },
);

test(
  "explorer account QR endpoint provides share-ready payloads",
  {
    timeout: 60_000,
  },
  async (t) => {
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
    });
    let defaultSnapshot;
    try {
      defaultSnapshot = await client.getExplorerAccountQr(AUTHORITY_ACCOUNT_ID);
    } catch (error) {
      if (isUnexpectedNotFoundError(error)) {
        t.diagnostic("explorer QR endpoint unavailable on target node; skipping assertions");
        return;
      }
      throw error;
    }

    assertExplorerAccountQrSnapshot(defaultSnapshot, "default explorer QR snapshot");
    const secondSnapshot = await client.getExplorerAccountQr(AUTHORITY_ACCOUNT_ID);
    assertExplorerAccountQrSnapshot(secondSnapshot, "second explorer QR snapshot");
    assert.equal(
      secondSnapshot.canonicalId,
      defaultSnapshot.canonicalId,
      "canonicalId must remain stable across repeated requests",
    );
    assert.equal(
      secondSnapshot.networkPrefix,
      defaultSnapshot.networkPrefix,
      "networkPrefix must remain stable across repeated requests",
    );
    assert.equal(
      secondSnapshot.literal,
      defaultSnapshot.literal,
      "literal should remain stable across repeated requests",
    );
  },
);

test(
  "sumeragi BLS key registry exposes peer map",
  {
    timeout: 60_000,
  },
  async (t) => {
    const keyMap = await OPERATOR_CLIENT.getSumeragiBlsKeys();
    assert.ok(keyMap && typeof keyMap === "object", "BLS key map must be an object");
    const entries = Object.entries(keyMap);
    if (entries.length === 0) {
      t.diagnostic("sumeragi BLS key registry returned zero entries");
    }
    for (const [peerId, blsHex] of entries) {
      assert.equal(typeof peerId, "string", "peer id must be a string");
      assert.notEqual(peerId.length, 0, "peer id must be non-empty");
      if (blsHex === null) {
        continue;
      }
      assertHexString(blsHex, `BLS key for ${peerId}`);
    }
  },
);

test(
  "sumeragi params snapshot exposes runtime configuration",
  {
    timeout: 60_000,
  },
  async (t) => {
    const params = await OPERATOR_CLIENT.getSumeragiParams();
    assert.ok(params && typeof params === "object", "params snapshot must be an object");
    assert.deepEqual(
      Object.keys(params).sort(),
      ["block_cadence_ms", "chain_height", "max_clock_drift_ms"],
      "params snapshot carries exactly the served fields",
    );
    assertNonNegativeInteger(params.block_cadence_ms, "sumeragi params block_cadence_ms");
    assert.ok(params.block_cadence_ms > 0, "sumeragi params block_cadence_ms must be nonzero");
    assertNonNegativeInteger(params.max_clock_drift_ms, "sumeragi params max_clock_drift_ms");
    assertNonNegativeInteger(params.chain_height, "sumeragi params chain_height");
  },
);

test(
  "governance unlock stats endpoint responds",
  {
    timeout: 60_000,
  },
  async (t) => {
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
    });
    const stats = await client.getGovernanceUnlockStatsTyped();
    assert.ok(stats, "unlock stats payload must be present");
    assert.equal(
      typeof stats.height_current,
      "number",
      "unlock stats height must be numeric",
    );
    assert.equal(
      typeof stats.expired_locks_now,
      "number",
      "unlock stats expired_locks_now must be numeric",
    );
    assert.equal(
      typeof stats.referenda_with_expired,
      "number",
      "unlock stats referenda_with_expired must be numeric",
    );
    assert.equal(
      typeof stats.last_sweep_height,
      "number",
      "unlock stats last_sweep_height must be numeric",
    );
    t.diagnostic(
      `governance unlock stats height=${stats.height_current} expired=${stats.expired_locks_now} last_sweep=${stats.last_sweep_height}`,
    );
  },
);

test(
  "governance protected namespaces endpoint responds",
  {
    timeout: 60_000,
  },
  async (t) => {
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
    });
    const response = await client.getProtectedNamespaces();
    assert.ok(response, "protected namespaces payload must be present");
    assert.equal(
      typeof response.found,
      "boolean",
      "protected namespaces response must include `found` flag",
    );
    assert.ok(
      Array.isArray(response.namespaces),
      "protected namespaces response must include an array",
    );
    for (const namespace of response.namespaces) {
      assert.equal(
        typeof namespace,
        "string",
        "protected namespaces entries must be strings",
      );
    }
    t.diagnostic(
      `protected namespaces found=${response.found} namespaces=${response.namespaces.join(",")}`,
    );
  },
);

test(
  "governance protected namespaces apply round-trips snapshot (optional)",
  {
    timeout: 60_000,
  },
  async (t) => {
    if (!MUTATION_ENABLED) {
      t.diagnostic("set IROHA_TORII_INTEGRATION_MUTATE=1 to enable governance mutation coverage");
      return;
    }
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
    });

    let baseline;
    try {
      baseline = await client.getProtectedNamespaces();
    } catch (error) {
      t.diagnostic(
        `protected namespaces endpoint unavailable: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
      return;
    }
    if (!baseline.found) {
      t.diagnostic(
        "protected namespaces configuration not found on the target node; skipping apply coverage",
      );
      return;
    }
    if (baseline.namespaces.length === 0) {
      t.diagnostic("protected namespaces list is empty; skipping apply coverage");
      return;
    }

    let applyResponse;
    try {
      applyResponse = await client.setProtectedNamespaces(baseline.namespaces);
    } catch (error) {
      t.diagnostic(
        `failed to reapply protected namespaces: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
      return;
    }

    assert.ok(applyResponse.ok, "protected namespaces apply should indicate success");
    assertNonNegativeInteger(
      applyResponse.applied,
      "protected namespaces apply response should include numeric applied count",
    );

    const confirmation = await client.getProtectedNamespaces();
    assert.ok(confirmation.found, "protected namespaces should remain available after apply");
    assert.deepEqual(
      confirmation.namespaces,
      baseline.namespaces,
      "protected namespaces apply should preserve the namespace snapshot",
    );
  },
);

test(
  "governance plain ballot draft (optional)",
  {
    timeout: 120_000,
  },
  async (t) => {
    if (!MUTATION_ENABLED) {
      t.diagnostic(
        "set IROHA_TORII_INTEGRATION_MUTATE=1 to enable governance ballot submission coverage",
      );
      return;
    }
    if (!GOVERNANCE_BALLOT_OPTIONS || !isPlainObject(GOVERNANCE_BALLOT_OPTIONS)) {
      t.diagnostic(
        "set IROHA_TORII_INTEGRATION_GOV_BALLOT to a JSON object with referendumId/owner/amount/durationBlocks/direction to exercise ballot submission coverage",
      );
      return;
    }
    let ballotPayload;
    try {
      ballotPayload = buildIntegrationGovernancePlainBallotPayload(
        GOVERNANCE_BALLOT_OPTIONS,
        { defaultAuthority: AUTHORITY_ACCOUNT_ID, networkId: NETWORK_ID },
      );
    } catch (error) {
      t.diagnostic(
        `invalid governance ballot payload from IROHA_TORII_INTEGRATION_GOV_BALLOT: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
      throw error;
    }
    if (!ballotPayload) {
      t.diagnostic(
        "set IROHA_TORII_INTEGRATION_GOV_BALLOT.referendumId to run the governance ballot submission coverage",
      );
      return;
    }

    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
      localSigningContext: new LocalSigningContext(NETWORK_ID, 753),
    });

    let response;
    try {
      response = await client.governanceSubmitPlainBallot(ballotPayload, {
        canonicalAuth: {
          accountId: ballotPayload.authority,
          privateKey: decodePrivateKeyHex(PRIVATE_KEY_HEX),
        },
      });
    } catch (error) {
      if (shouldSkipGovernanceBallotEndpoints(error)) {
        t.diagnostic(
          `governance ballot endpoint unavailable on target node: ${
            error instanceof Error ? error.message : String(error)
          }`,
        );
        return;
      }
      throw error;
    }

    assert.ok(response, "governance ballot response should be present");
    assert.equal(
      response.drafted,
      true,
      "governance ballot response should confirm an unsigned draft",
    );
    assert.ok(
      Array.isArray(response.tx_instructions),
      "governance ballot response must expose tx_instructions array",
    );
    assert.equal(
      response.tx_instructions.length,
      1,
      "governance ballot response must contain exactly one instruction",
    );
    response.tx_instructions.forEach((instruction, index) => {
      assert.ok(
        isNonEmptyString(instruction.wire_id),
        `governance ballot tx_instructions[${index}].wire_id must be a string`,
      );
      assertHexString(
        instruction.payload_hex,
        `governance ballot tx_instructions[${index}].payload_hex`,
      );
    });
    t.diagnostic(
      `governance ballot drafted=${response.drafted} instructions=${response.tx_instructions.length}`,
    );
  },
);

test(
  "ISO bridge pacs.008 submission (optional)",
  {
    timeout: 120_000,
  },
  async (t) => {
    if (!ISO_ENABLED) {
      t.diagnostic(
        "set IROHA_TORII_INTEGRATION_ISO_ENABLED=1 (and optionally IROHA_TORII_INTEGRATION_ISO_PACS008) to exercise ISO coverage",
      );
      return;
    }
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
    });
    const fields = buildIsoPacs008Fields(ISO_PACS008_OVERRIDES);
    const xmlPayload = buildPacs008Message(fields);
    try {
      const submission = await client.submitIsoPacs008(xmlPayload);
      assert.ok(
        submission?.message_id,
        "ISO submission should return a message_id for follow-up status queries",
      );
      const status = await client.getIsoMessageStatus(submission.message_id);
      assert.ok(
        status === null || typeof status === "object",
        "ISO status response should be structured when available",
      );
    } catch (error) {
      if (
        error instanceof Error &&
        error.message.includes("ISO bridge runtime is disabled on the target node")
      ) {
        t.diagnostic("ISO bridge runtime disabled on target node; skipping ISO submission test");
        return;
      }
      throw error;
    }
  },
);

test(
  "ISO bridge pacs.009 submission (optional)",
  {
    timeout: 120_000,
  },
  async (t) => {
    if (!ISO_ENABLED) {
      t.diagnostic(
        "set IROHA_TORII_INTEGRATION_ISO_ENABLED=1 (and optionally IROHA_TORII_INTEGRATION_ISO_PACS009) to exercise ISO coverage",
      );
      return;
    }
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
    });
    const fields = buildIsoPacs009Fields(ISO_PACS009_OVERRIDES);
    const xmlPayload = buildPacs009Message(fields);
    try {
      const submission = await client.submitIsoPacs009(xmlPayload);
      assert.ok(
        submission?.message_id,
        "ISO submission should return a message_id for follow-up status queries",
      );
      const status = await client.getIsoMessageStatus(submission.message_id);
      assert.ok(
        status === null || typeof status === "object",
        "ISO status response should be structured when available",
      );
    } catch (error) {
      if (
        error instanceof Error &&
        error.message.includes("ISO bridge runtime is disabled on the target node")
      ) {
        t.diagnostic("ISO bridge runtime disabled on target node; skipping ISO submission test");
        return;
      }
      throw error;
    }
  },
);

test(
  "ISO bridge waitForIsoMessageStatus polls message ids (optional)",
  {
    timeout: 180_000,
  },
  async (t) => {
    if (!ISO_ENABLED) {
      t.diagnostic("set IROHA_TORII_INTEGRATION_ISO_ENABLED=1 to exercise ISO status polling");
      return;
    }
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
    });
    const fields = buildIsoPacs008Fields(ISO_PACS008_OVERRIDES);
    const xmlPayload = buildPacs008Message(fields);
    let submission;
    try {
      submission = await client.submitIsoPacs008(xmlPayload);
    } catch (error) {
      if (isIsoBridgeDisabledError(error)) {
        t.diagnostic(`ISO bridge runtime disabled on target node: ${error.message}`);
        return;
      }
      t.diagnostic(
        `ISO pacs.008 submission failed before polling: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
      throw error;
    }
    const messageId = submission?.message_id;
    if (!isNonEmptyString(messageId)) {
      t.diagnostic(
        "ISO pacs.008 submission did not include message_id; cannot exercise waitForIsoMessageStatus",
      );
      return;
    }
    try {
      const status = await client.waitForIsoMessageStatus(messageId, {
        pollIntervalMs: ISO_POLL_INTERVAL_MS,
        maxAttempts: ISO_MAX_ATTEMPTS,
        resolveOnAcceptedWithoutTransaction: true,
      });
      assert.ok(status, "waitForIsoMessageStatus should resolve with a status payload");
      assert.ok(
        typeof status.status === "string" && status.status.length > 0,
        "waitForIsoMessageStatus payload must include a status string",
      );
      t.diagnostic(
        `waitForIsoMessageStatus resolved for message_id=${messageId} status=${status.status}`,
      );
    } catch (error) {
      if (isIsoBridgeDisabledError(error)) {
        t.diagnostic(`ISO bridge disabled while polling status: ${error.message}`);
        return;
      }
      if (error instanceof IsoMessageTimeoutError) {
        t.diagnostic(
          `waitForIsoMessageStatus timed out for message_id=${messageId} after ${ISO_MAX_ATTEMPTS} attempts`,
        );
        return;
      }
      throw error;
    }
  },
);

test(
  "ISO bridge wait helper surfaces timeout for unknown message ids (optional)",
  {
    timeout: 120_000,
  },
  async (t) => {
    if (!ISO_ENABLED) {
      t.diagnostic("set IROHA_TORII_INTEGRATION_ISO_ENABLED=1 to exercise ISO timeout coverage");
      return;
    }
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
    });
    const missingMessageId = randomIdentifier("iso-timeout-id-");
    try {
      await client.waitForIsoMessageStatus(missingMessageId, {
        pollIntervalMs: Math.max(ISO_POLL_INTERVAL_MS, 500),
        maxAttempts: 2,
        resolveOnAcceptedWithoutTransaction: true,
      });
      t.fail(`expected waitForIsoMessageStatus to time out for ${missingMessageId}`);
    } catch (error) {
      if (isIsoBridgeDisabledError(error)) {
        t.diagnostic(`ISO bridge disabled while polling status: ${error.message}`);
        return;
      }
      assert.ok(
        error instanceof IsoMessageTimeoutError,
        `expected IsoMessageTimeoutError when polling missing id (received ${error?.message ?? error})`,
      );
    }
  },
);

test(
  "ISO bridge pacs.008 wait helper (optional)",
  {
    timeout: 180_000,
  },
  async (t) => {
    if (!ISO_ENABLED) {
      t.diagnostic("set IROHA_TORII_INTEGRATION_ISO_ENABLED=1 to exercise ISO wait helpers");
      return;
    }
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
    });
    const fields = buildIsoPacs008Fields(ISO_PACS008_OVERRIDES);
    const xmlPayload = buildPacs008Message(fields);
    try {
      const status = await client.submitIsoPacs008AndWait(xmlPayload, {
        wait: {
          pollIntervalMs: ISO_POLL_INTERVAL_MS,
          maxAttempts: ISO_MAX_ATTEMPTS,
          resolveOnAcceptedWithoutTransaction: true,
        },
      });
      assert.ok(status, "ISO wait helper should return a status payload");
      assert.ok(
        typeof status.status === "string" && status.status.length > 0,
        "ISO status payload must include a status string",
      );
      t.diagnostic(
        `ISO pacs.008 wait helper resolved with status=${status.status} tx=${status.transaction_hash ?? "none"}`,
      );
    } catch (error) {
      if (isIsoBridgeDisabledError(error)) {
        t.diagnostic(`ISO bridge disabled on target node: ${error.message}`);
        return;
      }
      if (error instanceof IsoMessageTimeoutError) {
        t.diagnostic(
          `ISO pacs.008 wait helper timed out after ${ISO_MAX_ATTEMPTS} attempts: ${error.message}`,
        );
        return;
      }
      throw error;
    }
  },
);

test(
  "ISO bridge submitIsoMessage pacs.008 wait flow (optional)",
  {
    timeout: 120_000,
  },
  async (t) => {
    if (!ISO_ENABLED) {
      t.diagnostic("set IROHA_TORII_INTEGRATION_ISO_ENABLED=1 to exercise ISO submitIsoMessage coverage");
      return;
    }
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
    });
    const fields = buildIsoPacs008Fields(ISO_PACS008_OVERRIDES);
    try {
      const status = await client.submitIsoMessage(fields, {
        kind: "pacs.008",
        wait: {
          pollIntervalMs: ISO_POLL_INTERVAL_MS,
          maxAttempts: ISO_MAX_ATTEMPTS,
        },
      });
      assert.ok(status, "ISO submitIsoMessage pacs.008 helper should return a status payload");
      assert.equal(
        typeof status.status,
        "string",
        "ISO status payload must include a status string",
      );
      t.diagnostic(
        `ISO submitIsoMessage pacs.008 resolved with status=${status.status} tx=${status.transaction_hash ?? "none"}`,
      );
    } catch (error) {
      if (isIsoBridgeDisabledError(error)) {
        t.diagnostic(`ISO bridge disabled on target node: ${error.message}`);
        return;
      }
      if (error instanceof IsoMessageTimeoutError) {
        t.diagnostic(
          `ISO submitIsoMessage pacs.008 timed out after ${ISO_MAX_ATTEMPTS} attempts: ${error.message}`,
        );
        return;
      }
      throw error;
    }
  },
);

test(
  "ISO bridge submitIsoMessage pacs.009 wait flow (optional)",
  {
    timeout: 120_000,
  },
  async (t) => {
    if (!ISO_ENABLED) {
      t.diagnostic("set IROHA_TORII_INTEGRATION_ISO_ENABLED=1 to exercise ISO submitIsoMessage coverage");
      return;
    }
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
    });
    const fields = buildIsoPacs009Fields(ISO_PACS009_OVERRIDES);
    try {
      const status = await client.submitIsoMessage(fields, {
        kind: "pacs.009",
        wait: {
          pollIntervalMs: ISO_POLL_INTERVAL_MS,
          maxAttempts: ISO_MAX_ATTEMPTS,
          resolveOnAcceptedWithoutTransaction: true,
        },
      });
      assert.ok(status, "ISO submitIsoMessage pacs.009 helper should return a status payload");
      assert.equal(
        typeof status.status,
        "string",
        "ISO status payload must include a status string",
      );
      t.diagnostic(
        `ISO submitIsoMessage pacs.009 resolved with status=${status.status} tx=${status.transaction_hash ?? "none"}`,
      );
    } catch (error) {
      if (isIsoBridgeDisabledError(error)) {
        t.diagnostic(`ISO bridge disabled on target node: ${error.message}`);
        return;
      }
      if (error instanceof IsoMessageTimeoutError) {
        t.diagnostic(
          `ISO submitIsoMessage pacs.009 timed out after ${ISO_MAX_ATTEMPTS} attempts: ${error.message}`,
        );
        return;
      }
      throw error;
    }
  },
);

test(
  "ISO bridge submitIsoMessage pacs.009 default headers wait flow (optional)",
  {
    timeout: 120_000,
  },
  async (t) => {
    if (!ISO_ENABLED) {
      t.diagnostic("set IROHA_TORII_INTEGRATION_ISO_ENABLED=1 to exercise ISO submitIsoMessage coverage");
      return;
    }
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
    });
    const fields = buildIsoPacs009Fields({
      ...ISO_PACS009_OVERRIDES,
      messageId: undefined,
      businessMessageId: undefined,
      messageDefinitionId: undefined,
    });
    const instructionId = fields.instructionId;
    const xml = buildPacs009Message(fields);
    assert.match(
      xml,
      new RegExp(`<MsgId>${instructionId}</MsgId>`),
      "MsgId should use instruction id when omitted",
    );
    assert.match(
      xml,
      new RegExp(`<BizMsgIdr>${instructionId}</BizMsgIdr>`),
      "BizMsgIdr should use instruction id when omitted",
    );
    assert.match(
      xml,
      /<MsgDefIdr>pacs\.009\.001\.10<\/MsgDefIdr>/,
      "MsgDefIdr should default to pacs.009.001.10",
    );
    try {
      const status = await client.submitIsoMessage(fields, {
        kind: "pacs.009",
        wait: {
          pollIntervalMs: ISO_POLL_INTERVAL_MS,
          maxAttempts: ISO_MAX_ATTEMPTS,
          resolveOnAcceptedWithoutTransaction: true,
        },
      });
      assert.ok(status, "ISO submitIsoMessage pacs.009 helper should return a status payload");
      assert.equal(typeof status.status, "string", "ISO status payload must include a status string");
      t.diagnostic(
        `ISO submitIsoMessage pacs.009 (default headers) resolved with status=${status.status} tx=${status.transaction_hash ?? "none"}`,
      );
    } catch (error) {
      if (isIsoBridgeDisabledError(error)) {
        t.diagnostic(`ISO bridge disabled on target node: ${error.message}`);
        return;
      }
      if (error instanceof IsoMessageTimeoutError) {
        t.diagnostic(
          `ISO submitIsoMessage pacs.009 default headers timed out after ${ISO_MAX_ATTEMPTS} attempts: ${error.message}`,
        );
        return;
      }
      throw error;
    }
  },
);

test(
  "ISO bridge pacs.009 wait helper (optional)",
  {
    timeout: 180_000,
  },
  async (t) => {
    if (!ISO_ENABLED) {
      t.diagnostic("set IROHA_TORII_INTEGRATION_ISO_ENABLED=1 to exercise ISO wait helpers");
      return;
    }
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
    });
    const fields = buildIsoPacs009Fields(ISO_PACS009_OVERRIDES);
    const xmlPayload = buildPacs009Message(fields);
    try {
      const status = await client.submitIsoPacs009AndWait(xmlPayload, {
        wait: {
          pollIntervalMs: ISO_POLL_INTERVAL_MS,
          maxAttempts: ISO_MAX_ATTEMPTS,
          resolveOnAcceptedWithoutTransaction: true,
        },
      });
      assert.ok(status, "ISO wait helper should return a status payload");
      assert.ok(
        typeof status.status === "string" && status.status.length > 0,
        "ISO status payload must include a status string",
      );
      t.diagnostic(
        `ISO pacs.009 wait helper resolved with status=${status.status} tx=${status.transaction_hash ?? "none"}`,
      );
    } catch (error) {
      if (isIsoBridgeDisabledError(error)) {
        t.diagnostic(`ISO bridge disabled on target node: ${error.message}`);
        return;
      }
      if (error instanceof IsoMessageTimeoutError) {
        t.diagnostic(
          `ISO pacs.009 wait helper timed out after ${ISO_MAX_ATTEMPTS} attempts: ${error.message}`,
        );
        return;
      }
      throw error;
    }
  },
);

test(
  "ISO bridge alias resolution by label (optional)",
  {
    timeout: 60_000,
  },
  async (t) => {
    if (!ISO_ENABLED || !ISO_ALIAS_LABEL) {
      t.diagnostic(
        "set IROHA_TORII_INTEGRATION_ISO_ENABLED=1 and IROHA_TORII_INTEGRATION_ISO_ALIAS=<alias> to exercise alias resolution coverage",
      );
      return;
    }
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
    });
    try {
      const resolved = await client.resolveAlias(ISO_ALIAS_LABEL);
      if (!resolved) {
        t.diagnostic(
          `alias resolution returned null for ${ISO_ALIAS_LABEL}; ensure the alias exists on the target node`,
        );
        return;
      }
      assert.ok(
        typeof resolved.alias === "string" && resolved.alias.length > 0,
        "alias resolution must include the alias label",
      );
      assert.ok(
        typeof resolved.account_id === "string" && resolved.account_id.length > 0,
        "alias resolution must include the target account_id",
      );
      if (resolved.index !== undefined) {
        assert.equal(
          typeof resolved.index,
          "number",
          "alias resolution index must be numeric when present",
        );
      }
      if (resolved.source !== undefined) {
        assert.ok(
          typeof resolved.source === "string" && resolved.source.length > 0,
          "alias resolution source must be a non-empty string when present",
        );
      }
    } catch (error) {
      if (isIsoBridgeDisabledError(error)) {
        t.diagnostic(`ISO bridge disabled on target node: ${error.message}`);
        return;
      }
      throw error;
    }
  },
);

test(
  "ISO bridge alias resolution by index (optional)",
  {
    timeout: 60_000,
  },
  async (t) => {
    if (!ISO_ENABLED || !ISO_ALIAS_INDEX) {
      t.diagnostic(
        "set IROHA_TORII_INTEGRATION_ISO_ENABLED=1 and IROHA_TORII_INTEGRATION_ISO_ALIAS_INDEX=<integer> to exercise alias index coverage",
      );
      return;
    }
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
    });
    try {
      const resolved = await client.resolveAliasByIndex(ISO_ALIAS_INDEX);
      if (!resolved) {
        t.diagnostic(
          `alias resolve_index returned null for index ${ISO_ALIAS_INDEX}; ensure the index is valid on the target node`,
        );
        return;
      }
      assert.ok(
        typeof resolved.alias === "string" && resolved.alias.length > 0,
        "alias resolution must include the alias label",
      );
      assert.ok(
        typeof resolved.account_id === "string" && resolved.account_id.length > 0,
        "alias resolution must include the target account_id",
      );
      if (resolved.index !== undefined) {
        assert.equal(
          typeof resolved.index,
          "number",
          "alias resolution index must be numeric when present",
        );
      }
      if (resolved.source !== undefined) {
        assert.ok(
          typeof resolved.source === "string" && resolved.source.length > 0,
          "alias resolution source must be a non-empty string when present",
        );
      }
    } catch (error) {
      if (isIsoBridgeDisabledError(error)) {
        t.diagnostic(`ISO bridge disabled on target node: ${error.message}`);
        return;
      }
      throw error;
    }
  },
);

test(
  "ISO bridge alias resolution returns null for missing entries (optional)",
  {
    timeout: 60_000,
  },
  async (t) => {
    if (!ISO_ENABLED) {
      t.diagnostic("set IROHA_TORII_INTEGRATION_ISO_ENABLED=1 to exercise alias-missing coverage");
      return;
    }
    const client = new ToriiClient(BASE_URL, {
      authToken: AUTH_TOKEN,
      apiToken: API_TOKEN,
    });
    const unlikelyAlias = randomIdentifier("js-missing-alias-");
    try {
      const resolved = await client.resolveAlias(unlikelyAlias);
      assert.equal(
        resolved,
        null,
        `expected resolveAlias to return null for missing alias ${unlikelyAlias}`,
      );
    } catch (error) {
      if (isIsoBridgeDisabledError(error)) {
        t.diagnostic(`ISO bridge disabled on target node: ${error.message}`);
        return;
      }
      throw error;
    }
  },
);

async function waitForPipelineBlockEvent(client, signal) {
  const iterator = client.streamEvents({
    filter: { Pipeline: { Block: {} } },
    signal,
  });
  for await (const event of iterator) {
    if (event?.data?.Pipeline?.Block) {
      return event;
    }
  }
  throw new Error("pipeline event stream closed before emitting a block payload");
}

function assertPipelineBlockEvent(event) {
  assert.ok(event, "expected streamEvents to yield an event payload");
  assert.ok(isNonEmptyString(event?.id), "pipeline event must include an id");
  assert.ok(
    event?.data?.Pipeline?.Block,
    "pipeline event must contain a Pipeline.Block payload",
  );
  const payload = event.data.Pipeline.Block;
  if (payload.height !== undefined) {
    assert.equal(typeof payload.height, "number", "block event height must be numeric when present");
  }
  if (payload.hash !== undefined) {
    assert.ok(
      isNonEmptyString(payload.hash),
      "block event hash must be a non-empty string when present",
    );
  }
}

async function withTimeout(promise, timeoutMs, message) {
  let timeoutId;
  const timeoutPromise = new Promise((_, reject) => {
    timeoutId = setTimeout(() => reject(new Error(message)), timeoutMs);
  });
  try {
    return await Promise.race([promise, timeoutPromise]);
  } finally {
    clearTimeout(timeoutId);
  }
}

function decodePrivateKeyHex(hexLiteral) {
  const trimmed = hexLiteral.trim();
  if (!trimmed) {
    throw new Error("private key hex must not be empty");
  }
  if (trimmed.length % 2 !== 0) {
    throw new Error("private key hex must have an even length");
  }
  return Buffer.from(trimmed, "hex");
}

function randomDomainId() {
  return randomIdentifier("jsintegration");
}

function randomAccountId() {
  const label = randomIdentifier("jsacct");
  const publicKey = crypto
    .createHash("sha256")
    .update(`account:${label}`)
    .digest();
  return AccountAddress.fromAccount({ publicKey }).toI105();
}

function randomAssetDefinitionId() {
  const value =
    INTEGRATION_ASSET_DEFINITION_IDS[
      randomAssetDefinitionCounter % INTEGRATION_ASSET_DEFINITION_IDS.length
    ];
  randomAssetDefinitionCounter += 1;
  return value;
}

function composeAssetId(assetDefinitionId, accountId, dataspaceId = null) {
  const base = `${assetDefinitionId}#${accountId}`;
  return dataspaceId === null ? base : `${base}#dataspace:${dataspaceId}`;
}

function randomTriggerId(namespace = "apps") {
  const suffix = randomIdentifier("trigger");
  return `${namespace}::${suffix}`;
}

function randomIdentifier(prefix) {
  return `${prefix}${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;
}

function assertSuccessfulStatus(status, referenceId) {
  assert.ok(status, "expected submitTransactionAndWait to return a payload");
  assert.equal(
    status.status?.kind,
    "Applied",
    `transaction for ${referenceId} did not reach Applied finality`,
  );
  assert.equal(status.scope, "global");
  assert.equal(status.resolved_from, "state");
}

async function waitForSumeragiStatusEvent(client, signal) {
  const iterator = client.streamSumeragiStatus({ signal });
  for await (const event of iterator) {
    if (event?.data && typeof event.data === "object") {
      return event;
    }
  }
  throw new Error("sumeragi status stream closed before emitting a payload");
}

function assertSumeragiStatusEvent(event) {
  assert.ok(event, "expected streamSumeragiStatus to yield an event payload");
  assert.ok(
    event?.data && typeof event.data === "object",
    "sumeragi status event must expose a JSON payload",
  );
  const snapshot = event.data;
  assert.equal(snapshot.protocol_version, 4, "sumeragi status event must use wire revision 4");
  assert.ok(
    snapshot.height_context && typeof snapshot.height_context === "object",
    "sumeragi status event must include height_context",
  );
  assert.ok(
    Array.isArray(snapshot.lane_settlement_commitments),
    "sumeragi status event must include lane_settlement_commitments array",
  );
  assert.ok(
    Array.isArray(snapshot.lane_relay_envelopes),
    "sumeragi status event must include lane_relay_envelopes array",
  );
  assert.ok(
    Array.isArray(snapshot.lane_payload_ownerships),
    "sumeragi status event must include lane_payload_ownerships array",
  );
  assert.ok(
    Array.isArray(snapshot.committed_lane_blocks),
    "sumeragi status event must include committed_lane_blocks array",
  );
  assert.ok(
    Array.isArray(snapshot.lane_block_sessions),
    "sumeragi status event must include lane_block_sessions array",
  );
  assert.equal(typeof snapshot.local_peer_removed, "boolean");
  assert.ok(snapshot.operator && typeof snapshot.operator === "object");
}

function assertUaidPortfolioSnapshot(snapshot, expectedUaid) {
  assert.ok(snapshot && typeof snapshot === "object", "uaid portfolio snapshot must be an object");
  assert.equal(
    snapshot.uaid,
    expectedUaid,
    "uaid portfolio response must echo the requested UAID",
  );
  assert.ok(snapshot.totals && typeof snapshot.totals === "object");
  assert.equal(typeof snapshot.totals.accounts, "number");
  assert.equal(typeof snapshot.totals.positions, "number");
  assert.ok(Array.isArray(snapshot.dataspaces), "uaid portfolio dataspaces must be an array");
  snapshot.dataspaces.forEach((dataspace, index) => {
    assert.equal(
      typeof dataspace.dataspace_id,
      "number",
      `portfolio dataspaces[${index}].dataspace_id must be numeric`,
    );
    assert.ok(
      Array.isArray(dataspace.accounts),
      `portfolio dataspaces[${index}].accounts must be an array`,
    );
    dataspace.accounts.forEach((account, accountIndex) => {
      assert.ok(
        typeof account.account_id === "string" && account.account_id.length > 0,
        `portfolio dataspaces[${index}].accounts[${accountIndex}].account_id must be a string`,
      );
      assert.ok(
        Array.isArray(account.assets),
        `portfolio dataspaces[${index}].accounts[${accountIndex}].assets must be an array`,
      );
      account.assets.forEach((asset, assetIndex) => {
        assert.ok(
          typeof asset.asset_id === "string" && asset.asset_id.length > 0,
          `portfolio dataspaces[${index}].accounts[${accountIndex}].assets[${assetIndex}].asset_id must be string`,
        );
        assert.ok(
          typeof asset.asset_definition_id === "string" &&
            asset.asset_definition_id.length > 0,
          `portfolio dataspaces[${index}].accounts[${accountIndex}].assets[${assetIndex}].asset_definition_id must be string`,
        );
        assert.ok(
          typeof asset.quantity === "string" && asset.quantity.length > 0,
          `portfolio dataspaces[${index}].accounts[${accountIndex}].assets[${assetIndex}].quantity must be string`,
        );
      });
    });
  });
}

function assertUaidBindingsSnapshot(snapshot, expectedUaid) {
  assert.ok(snapshot && typeof snapshot === "object", "uaid bindings snapshot must be an object");
  assert.equal(
    snapshot.uaid,
    expectedUaid,
    "uaid bindings response must echo the requested UAID",
  );
  assert.ok(Array.isArray(snapshot.dataspaces), "uaid bindings dataspaces must be an array");
  snapshot.dataspaces.forEach((dataspace, index) => {
    assert.equal(
      typeof dataspace.dataspace_id,
      "number",
      `bindings dataspaces[${index}].dataspace_id must be numeric`,
    );
    assert.ok(
      Array.isArray(dataspace.accounts),
      `bindings dataspaces[${index}].accounts must be an array`,
    );
  });
}

function assertUaidManifestsSnapshot(snapshot, expectedUaid) {
  assert.ok(snapshot && typeof snapshot === "object", "uaid manifests snapshot must be an object");
  assert.ok(snapshot.nextCursor === null || typeof snapshot.nextCursor === "string");
  assert.ok(Array.isArray(snapshot.items), "uaid manifests array must be present");
  snapshot.items.forEach((record, index) => {
    assert.equal(record.manifest.uaid, expectedUaid);
    assert.equal(
      typeof record.dataspace_id,
      "number",
      `manifests[${index}].dataspace_id must be numeric`,
    );
    assert.ok(
      typeof record.status === "string" && record.status.length > 0,
      `manifests[${index}].status must be a string`,
    );
    assert.ok(
      typeof record.manifest_hash === "string" && record.manifest_hash.length > 0,
      `manifests[${index}].manifest_hash must be string`,
    );
    assert.ok(
      record.lifecycle && typeof record.lifecycle === "object",
      `manifests[${index}].lifecycle must be an object`,
    );
    assert.ok(
      Array.isArray(record.accounts),
      `manifests[${index}].accounts must be an array`,
    );
    assert.ok(
      record.manifest && typeof record.manifest === "object",
      `manifests[${index}].manifest must be an object`,
    );
    assert.ok(
      Array.isArray(record.manifest.entries),
      `manifests[${index}].manifest.entries must be an array`,
    );
  });
}

function assertSnsPolicySnapshot(policy, expectedSuffixId) {
  assert.ok(policy && typeof policy === "object", "sns policy response must be an object");
  assert.equal(
    policy.suffixId,
    expectedSuffixId,
    "sns policy response must echo the requested suffix id",
  );
  assert.ok(
    typeof policy.suffix === "string" && policy.suffix.length > 0,
    "sns policy suffix must be a non-empty string",
  );
  assert.ok(typeof policy.steward === "string" && policy.steward.length > 0);
  assert.ok(typeof policy.status === "string" && policy.status.length > 0);
  assertNonNegativeInteger(policy.minTermYears, "sns policy minTermYears");
  assertNonNegativeInteger(policy.maxTermYears, "sns policy maxTermYears");
  assertNonNegativeInteger(policy.gracePeriodDays, "sns policy gracePeriodDays");
  assertNonNegativeInteger(policy.redemptionPeriodDays, "sns policy redemptionPeriodDays");
  assertNonNegativeInteger(policy.referralCapBps, "sns policy referralCapBps");
  assert.ok(Array.isArray(policy.reservedLabels), "sns policy reservedLabels must be an array");
  policy.reservedLabels.forEach((label, index) => {
    assert.ok(
      label && typeof label === "object",
      `sns policy reservedLabels[${index}] must be an object`,
    );
    assert.ok(
      typeof label.normalizedLabel === "string" && label.normalizedLabel.length > 0,
      `sns policy reservedLabels[${index}].normalizedLabel must be a non-empty string`,
    );
  });
  assert.ok(Array.isArray(policy.pricing), "sns policy pricing must be an array");
  policy.pricing.forEach((tier, index) => {
    assert.ok(tier && typeof tier === "object", `sns policy pricing[${index}] must be object`);
    assertNonNegativeInteger(tier.tierId, `sns policy pricing[${index}].tierId`);
    assert.ok(
      typeof tier.labelRegex === "string" && tier.labelRegex.length > 0,
      `sns policy pricing[${index}].labelRegex must be a string`,
    );
  });
}

function assertSnsNameRecord(record, expectedSelector) {
  assert.ok(record && typeof record === "object", "sns name record must be an object");
  assert.ok(
    record.selector && typeof record.selector === "object",
    "sns name record selector must be an object",
  );
  assert.ok(
    typeof record.selector.label === "string" && record.selector.label.length > 0,
    "sns name record selector.label must be a non-empty string",
  );
  assert.ok(
    typeof record.selector.suffix_id === "number",
    "sns name record selector.suffix_id must be numeric",
  );
  assert.ok(
    typeof record.selector.version === "number",
    "sns name record selector.version must be numeric",
  );
  if (typeof expectedSelector === "string" && expectedSelector.length > 0) {
    assert.ok(
      expectedSelector.includes(record.selector.label),
      "sns name record selector label should match the requested selector label",
    );
  }
  assertHexString(record.nameHash, "sns name record nameHash");
  assert.ok(
    typeof record.owner === "string" && record.owner.length > 0,
    "sns name record owner must be a non-empty string",
  );
  assert.ok(Array.isArray(record.controllers), "sns name record controllers must be an array");
  assert.ok(record.status && typeof record.status === "object", "sns name status must be an object");
  assert.ok(
    typeof record.status.status === "string" && record.status.status.length > 0,
    "sns name status.status must be a non-empty string",
  );
  assertNonNegativeInteger(record.pricingClass, "sns name record pricingClass");
  assertNonNegativeInteger(record.registeredAtMs, "sns name record registeredAtMs");
  assertNonNegativeInteger(record.expiresAtMs, "sns name record expiresAtMs");
}

function assetDefinitionOf(assetHoldingId) {
  const separator = assetHoldingId.indexOf("#");
  return separator === -1 ? assetHoldingId : assetHoldingId.slice(0, separator);
}

async function findAccountAsset(client, accountId, assetHoldingId) {
  const definitionId = assetDefinitionOf(assetHoldingId);
  for await (const asset of client.accountAssets(accountId).iterate({
    filter: field("asset").eq(definitionId),
    limit: 10,
  })) {
    if (asset?.asset === definitionId) {
      return asset;
    }
  }
  return null;
}

async function iteratorIncludes(iterator, predicate) {
  for await (const item of iterator) {
    if (predicate(item)) {
      return true;
    }
  }
  return false;
}

async function waitForDaManifest(client, ticketHex, options = {}) {
  const attempts = options.attempts ?? 5;
  const intervalMs = options.intervalMs ?? 2_000;
  let lastError = null;
  for (let index = 0; index < attempts; index += 1) {
    try {
      return await client.getDaManifest(ticketHex);
    } catch (error) {
      lastError = error;
      if (!shouldRetryDaManifestFetch(error)) {
        throw error;
      }
      await delay(intervalMs);
    }
  }
  const message =
    lastError instanceof Error ? lastError.message : String(lastError ?? "unknown error");
  throw new Error(`da manifest for ${ticketHex} unavailable after ${attempts} attempts: ${message}`);
}

function shouldRetryDaManifestFetch(error) {
  if (!error) {
    return false;
  }
  const message = error instanceof Error ? error.message : String(error);
  return /404/.test(message) || /not\s+found/i.test(message);
}

async function waitForAttachmentDeletion(client, attachmentId, canonicalAuth, attempts = 3, delayMs = 500) {
  for (let index = 0; index < attempts; index += 1) {
    try {
      await client.getAttachment(attachmentId, { canonicalAuth });
    } catch (error) {
      if (isAttachmentNotFoundError(error) || isAttachmentEndpointUnavailable(error)) {
        return true;
      }
      throw error;
    }
    await delay(delayMs);
  }
  return false;
}

async function waitForUaidManifestRecord(client, uaidLiteral, dataspaceId, options = {}) {
  const {
    attempts = 5,
    delayMs = 1_000,
    predicate = () => true,
  } = options;
  let lastError = null;
  let lastSnapshot = null;
  for (let index = 0; index < attempts; index += 1) {
    try {
      const snapshot = await client.uaidManifests(uaidLiteral).list({
        filter: `dataspace_id = ${dataspaceId}`,
      });
      assertUaidManifestsSnapshot(snapshot, uaidLiteral);
      lastSnapshot = snapshot;
      const record =
        snapshot.items.find(
          (entry) => entry && entry.dataspace_id === dataspaceId,
        ) ?? null;
      if (record && predicate(record)) {
        return { record, snapshot };
      }
    } catch (error) {
      lastError = error;
    }
    await delay(delayMs);
  }
  if (lastSnapshot) {
    throw new Error(
      `Space Directory manifest for dataspace ${dataspaceId} not ready after ${attempts} attempts (last manifest count=${lastSnapshot.items.length})`,
    );
  }
  if (lastError) {
    throw new Error(
      `Space Directory manifest fetch failed after ${attempts} attempts: ${
        lastError instanceof Error ? lastError.message : String(lastError)
      }`,
    );
  }
  throw new Error(
    `Space Directory manifest record not observed for dataspace ${dataspaceId} after ${attempts} attempts`,
  );
}

function delay(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function resolveProjectPath(rawPath) {
  if (path.isAbsolute(rawPath)) {
    return rawPath;
  }
  return path.resolve(PROJECT_ROOT, rawPath);
}

function loadSpaceDirectoryManifestFixture() {
  const trimmed = normalizeIntegrationString(SPACE_DIRECTORY_MANIFEST_PATH);
  if (!trimmed) {
    throw new Error(
      "set IROHA_TORII_INTEGRATION_SPACE_DIRECTORY_MANIFEST=/path/to/manifest.json to exercise Space Directory coverage",
    );
  }
  const resolvedPath = resolveProjectPath(trimmed);
  let manifestText;
  try {
    manifestText = fs.readFileSync(resolvedPath, "utf8");
  } catch (error) {
    throw new Error(
      `failed to read Space Directory manifest fixture ${resolvedPath}`,
      { cause: error },
    );
  }
  let manifest;
  try {
    manifest = JSON.parse(manifestText);
  } catch (error) {
    throw new Error(
      `failed to parse Space Directory manifest fixture ${resolvedPath}`,
      { cause: error },
    );
  }
  return { manifest, path: resolvedPath };
}

function canonicalizeSpaceDirectoryManifest(input) {
  const manifest = JSON.parse(JSON.stringify(input));
  if (manifest.version === undefined || manifest.version === null) {
    manifest.version = "1";
  } else if (typeof manifest.version !== "string") {
    manifest.version = String(manifest.version);
  }
  return manifest;
}

function coerceNonNegativeInteger(value) {
  if (value === undefined || value === null) {
    return null;
  }
  if (typeof value === "number" && Number.isFinite(value) && value >= 0) {
    return value;
  }
  if (typeof value === "string" && value.trim().length > 0) {
    const parsed = Number.parseInt(value.trim(), 10);
    if (Number.isFinite(parsed) && parsed >= 0) {
      return parsed;
    }
  }
  return null;
}

function buildIsoPacs008Fields(overrides) {
  const now = new Date();
  const settlementDate = new Date(now.getTime() + 24 * 60 * 60 * 1000)
    .toISOString()
    .slice(0, 10);
  const base = {
    messageId: randomIsoId("msg"),
    creationDateTime: now.toISOString(),
    instructionId: randomIsoId("instr"),
    endToEndId: randomIsoId("e2e"),
    transactionId: randomIsoId("tx"),
    settlementDate,
    amount: { currency: "USD", value: "5.00" },
    instigatingAgent: { bic: "DEUTDEFF", lei: "529900ODI3047E2LIV03" },
    instructedAgent: { bic: "COBADEFF" },
    debtorAccount: { iban: "DE89370400440532013000" },
    creditorAccount: { otherId: "34mSYnDgbaJM58rbLoif4Tkp7G4LTcGTWkBnWUGuYYFogLyNhhuq386y2zQoSXk5oi1iY4YYx" },
    purposeCode: "SECU",
    supplementaryData: {
      suite: "js-integration",
    },
  };
  const fields = deepMerge(base, overrides);
  fields.nexusSettlement = {
    ...fields.nexusSettlement,
    networkId: NetworkId.parse(fields.nexusSettlement?.networkId),
  };
  return fields;
}

function buildIsoPacs009Fields(overrides) {
  const now = new Date();
  const settlementDate = new Date(now.getTime() + 48 * 60 * 60 * 1000)
    .toISOString()
    .slice(0, 10);
  const base = {
    messageId: randomIsoId("msg009"),
    businessMessageId: randomIsoId("biz009"),
    messageDefinitionId: "pacs.009.001.10",
    creationDateTime: now.toISOString(),
    instructionId: randomIsoId("instr009"),
    transactionId: randomIsoId("tx009"),
    settlementDate,
    amount: { currency: "USD", value: "10.00" },
    instigatingAgent: { bic: "DEUTDEFF", lei: "529900ODI3047E2LIV03" },
    instructedAgent: { bic: "COBADEFF" },
    purposeCode: "TRAD",
    supplementaryData: {
      suite: "js-integration",
    },
  };
  const fields = deepMerge(base, overrides);
  fields.nexusSettlement = {
    ...fields.nexusSettlement,
    networkId: NetworkId.parse(fields.nexusSettlement?.networkId),
  };
  return fields;
}

function deepMerge(target, source) {
  const result = Array.isArray(target) ? [...target] : { ...target };
  if (!source || typeof source !== "object") {
    return result;
  }
  for (const [key, value] of Object.entries(source)) {
    if (value && typeof value === "object" && !Array.isArray(value)) {
      const prior = result[key];
      result[key] = deepMerge(
        prior && typeof prior === "object" ? prior : {},
        value,
      );
    } else {
      result[key] = value;
    }
  }
  return result;
}

function randomIsoId(prefix) {
  return `${prefix}-${Date.now().toString(36)}-${Math.random()
    .toString(36)
    .slice(2, 10)}`;
}

function parseJsonEnv(rawValue) {
  if (!rawValue) {
    return null;
  }
  try {
    return JSON.parse(rawValue);
  } catch (error) {
    throw new Error(
      `failed to parse JSON from environment variable: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
}

function parsePositiveIntegerEnv(rawValue, defaultValue) {
  if (!rawValue) {
    return defaultValue;
  }
  const parsed = Number.parseInt(rawValue, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(
      `expected positive integer but received \`${rawValue}\` for ISO integration settings`,
    );
  }
  return parsed;
}

function parseUnsignedIntegerEnv(rawValue, { allowZero = false } = {}) {
  if (!rawValue) {
    return null;
  }
  const trimmed = rawValue.trim();
  if (!trimmed) {
    return null;
  }
  const parsed = Number.parseInt(trimmed, 10);
  const isValid = Number.isFinite(parsed) && parsed >= 0 && (allowZero || parsed > 0);
  if (!isValid) {
    throw new Error(
      `expected ${allowZero ? "non-negative" : "positive"} integer but received \`${rawValue}\` for UAID integration settings`,
    );
  }
  return parsed;
}

function isIsoBridgeDisabledError(error) {
  if (!(error instanceof Error)) {
    return false;
  }
  const message = error.message ?? "";
  return (
    message.includes("ISO bridge runtime is disabled") ||
    message.includes("ISO bridge is disabled") ||
    message.includes("ISO bridge runtime disabled")
  );
}

function isAttachmentEndpointUnavailable(error) {
  return (
    error instanceof ToriiHttpError &&
    (error.status === 404 ||
      error.status === 405 ||
      error.status === 403 ||
      error.status === 501)
  );
}

function isAttachmentNotFoundError(error) {
  return error instanceof ToriiHttpError && (error.status === 404 || error.status === 410);
}

function shouldSkipTriggerEndpoints(error) {
  if (!(error instanceof Error)) {
    return false;
  }
  const message = error.message ?? "";
  return (
    isUnexpectedNotFoundError(error) ||
    (/trigger/i.test(message) &&
      (/disabled/i.test(message) || /unexpected status 503/i.test(message)))
  );
}

function shouldSkipGovernanceBallotEndpoints(error) {
  if (error instanceof ToriiHttpError) {
    return error.status === 404 || error.status === 501 || error.status === 503;
  }
  if (!(error instanceof Error)) {
    return false;
  }
  const message = error.message ?? "";
  return /ballot/i.test(message) && /disabled/i.test(message);
}

function isUnexpectedNotFoundError(error) {
  return error instanceof Error && /unexpected status 404/i.test(error.message ?? "");
}

function assertExplorerAccountQrSnapshot(snapshot, label) {
  assert.ok(isPlainObject(snapshot), `${label} must be an object`);
  assert.equal(typeof snapshot.canonicalId, "string", `${label}.canonicalId must be a string`);
  assert.notEqual(snapshot.canonicalId.length, 0, `${label}.canonicalId must not be empty`);
  assert.equal(typeof snapshot.literal, "string", `${label}.literal must be a string`);
  assert.notEqual(snapshot.literal.length, 0, `${label}.literal must not be empty`);
  assert.ok(
    Number.isInteger(snapshot.networkPrefix) && snapshot.networkPrefix > 0,
    `${label}.networkPrefix must be a positive integer`,
  );
  assert.equal(
    typeof snapshot.errorCorrection,
    "string",
    `${label}.errorCorrection must be a string`,
  );
  assert.notEqual(
    snapshot.errorCorrection.length,
    0,
    `${label}.errorCorrection must not be empty`,
  );
  assert.ok(
    Number.isInteger(snapshot.modules) && snapshot.modules > 0,
    `${label}.modules must be a positive integer`,
  );
  assert.ok(
    Number.isInteger(snapshot.qrVersion) && snapshot.qrVersion > 0,
    `${label}.qrVersion must be a positive integer`,
  );
  assert.equal(typeof snapshot.svg, "string", `${label}.svg must be a string`);
  assert.ok(snapshot.svg.startsWith("<svg"), `${label}.svg must contain an <svg> payload`);
}
function assertKaigiRelaySummaryList(list) {
  assertNonNegativeInteger(list.total, "kaigi relay list total");
  assert.ok(Array.isArray(list.items), "kaigi relay list items must be an array");
  list.items.forEach((entry, index) => {
    assertKaigiRelaySummary(entry, `kaigi relay summary[${index}]`);
  });
}

function assertKaigiRelaySummary(summary, label = "kaigi relay summary") {
  assert.ok(isPlainObject(summary), `${label} must be an object`);
  assert.ok(isNonEmptyString(summary.relay_id), `${label}.relay_id must be a string`);
  assert.ok(isNonEmptyString(summary.domain), `${label}.domain must be a string`);
  assertNonNegativeInteger(summary.bandwidth_class, `${label}.bandwidth_class`);
  assert.ok(
    isNonEmptyString(summary.hpke_fingerprint_hex),
    `${label}.hpke_fingerprint_hex must be a string`,
  );
  if (summary.status !== undefined && summary.status !== null) {
    assert.ok(
      KAIGI_HEALTH_STATUSES.has(summary.status),
      `${label}.status must be healthy, degraded, or unavailable`,
    );
  }
  if (summary.reported_at_ms !== undefined && summary.reported_at_ms !== null) {
    assertNonNegativeInteger(summary.reported_at_ms, `${label}.reported_at_ms`);
  }
}

function assertKaigiRelayDetail(detail, relayId) {
  assert.ok(detail && typeof detail === "object", "kaigi relay detail must be an object");
  assert.equal(
    typeof detail.hpke_public_key_b64,
    "string",
    "kaigi relay detail hpke_public_key_b64 must be a string",
  );
  assertKaigiRelaySummary(detail.relay, "kaigi relay detail.relay");
  if (detail.reported_call !== undefined && detail.reported_call !== null) {
    assert.equal(typeof detail.reported_call, "object", "kaigi relay detail reported_call must be an object");
    assert.ok(
      isNonEmptyString(detail.reported_call.domain_id),
      "kaigi relay detail reported_call.domain_id must be a string",
    );
    assert.ok(
      isNonEmptyString(detail.reported_call.call_name),
      "kaigi relay detail reported_call.call_name must be a string",
    );
  }
  if (detail.reported_by !== undefined && detail.reported_by !== null) {
    assert.ok(
      isNonEmptyString(detail.reported_by),
      "kaigi relay detail reported_by must be a string when present",
    );
  }
  if (detail.notes !== undefined && detail.notes !== null) {
    assert.equal(typeof detail.notes, "string", "kaigi relay detail notes must be a string");
  }
  if (detail.metrics) {
    assertKaigiRelayDomainMetrics(detail.metrics, "kaigi relay detail.metrics");
  }
  assert.equal(
    detail.relay.relay_id,
    relayId,
    "kaigi relay detail relay_id should match the requested relay id",
  );
}

function assertKaigiRelayHealthSnapshot(snapshot) {
  assert.ok(snapshot && typeof snapshot === "object", "kaigi relay health snapshot must be an object");
  assertNonNegativeInteger(snapshot.healthy_total, "kaigi relay health healthy_total");
  assertNonNegativeInteger(snapshot.degraded_total, "kaigi relay health degraded_total");
  assertNonNegativeInteger(snapshot.unavailable_total, "kaigi relay health unavailable_total");
  assertNonNegativeInteger(snapshot.reports_total, "kaigi relay health reports_total");
  assertNonNegativeInteger(snapshot.registrations_total, "kaigi relay health registrations_total");
  assertNonNegativeInteger(snapshot.failovers_total, "kaigi relay health failovers_total");
  assert.ok(
    Array.isArray(snapshot.domains),
    "kaigi relay health domains must be an array",
  );
  snapshot.domains.forEach((metrics, index) => {
    assertKaigiRelayDomainMetrics(metrics, `kaigi relay health domains[${index}]`);
  });
}

function assertKaigiRelayDomainMetrics(metrics, label) {
  assert.ok(metrics && typeof metrics === "object", `${label} must be an object`);
  assert.ok(isNonEmptyString(metrics.domain), `${label}.domain must be a string`);
  assertNonNegativeInteger(metrics.registrations_total, `${label}.registrations_total`);
  assertNonNegativeInteger(metrics.manifest_updates_total, `${label}.manifest_updates_total`);
  assertNonNegativeInteger(metrics.failovers_total, `${label}.failovers_total`);
  assertNonNegativeInteger(metrics.health_reports_total, `${label}.health_reports_total`);
}

function assertVerifyingKeyListEntry(entry, label = "verifying key summary") {
  assert.ok(isPlainObject(entry), `${label} must be an object`);
  assertVerifyingKeyIdentifier(entry.id, `${label}.id`);
  if (entry.record !== undefined && entry.record !== null) {
    assertVerifyingKeyRecord(entry.record, `${label}.record`);
  }
}

function assertVerifyingKeyIdentifier(id, label = "verifying key id") {
  assert.ok(isPlainObject(id), `${label} must be an object`);
  assert.ok(isNonEmptyString(id.backend), `${label}.backend must be a string`);
  assert.ok(isNonEmptyString(id.name), `${label}.name must be a string`);
}

function assertVerifyingKeyDetail(detail, expectedId = null) {
  assert.ok(isPlainObject(detail), "verifying key detail must be an object");
  assertVerifyingKeyIdentifier(detail.id, "verifying key detail.id");
  if (expectedId) {
    assert.equal(detail.id.backend, expectedId.backend, "verifying key detail backend mismatch");
    assert.equal(detail.id.name, expectedId.name, "verifying key detail name mismatch");
  }
  assertVerifyingKeyRecord(detail.record, "verifying key detail.record");
  assert.ok(
    isNonEmptyString(detail.record_norito_base64),
    "verifying key detail.record_norito_base64 must be a string",
  );
}

function assertVerifyingKeyRecord(record, label = "verifying key record") {
  assert.ok(isPlainObject(record), `${label} must be an object`);
  assertNonNegativeInteger(record.version, `${label}.version`);
  assert.ok(isNonEmptyString(record.circuit_id), `${label}.circuit_id must be a string`);
  if (record.owner_manifest_id !== null) {
    assert.ok(
      isNonEmptyString(record.owner_manifest_id),
      `${label}.owner_manifest_id must be a string when present`,
    );
  }
  assert.ok(isNonEmptyString(record.namespace), `${label}.namespace must be a string`);
  assert.ok(isNonEmptyString(record.backend), `${label}.backend must be a string`);
  assert.ok(isNonEmptyString(record.curve), `${label}.curve must be a string`);
  assertHexString(record.public_inputs_schema_hash, `${label}.public_inputs_schema_hash`);
  assertHexString(record.commitment_hex, `${label}.commitment_hex`);
  assertNonNegativeInteger(record.vk_len, `${label}.vk_len`);
  assertNonNegativeInteger(record.max_proof_bytes, `${label}.max_proof_bytes`);
  if (record.gas_schedule_id !== null) {
    assert.ok(isNonEmptyString(record.gas_schedule_id), `${label}.gas_schedule_id must be a string`);
  }
  if (record.metadata_uri_cid !== null) {
    assert.ok(
      isNonEmptyString(record.metadata_uri_cid),
      `${label}.metadata_uri_cid must be a string`,
    );
  }
  if (record.vk_bytes_cid !== null) {
    assert.ok(isNonEmptyString(record.vk_bytes_cid), `${label}.vk_bytes_cid must be a string`);
  }
  if (record.activation_height !== null) {
    assertNonNegativeInteger(record.activation_height, `${label}.activation_height`);
  }
  if (record.deprecation_height !== null) {
    assertNonNegativeInteger(record.deprecation_height, `${label}.deprecation_height`);
  }
  if (record.withdraw_height !== null) {
    assertNonNegativeInteger(record.withdraw_height, `${label}.withdraw_height`);
  }
  if (record.status !== undefined && record.status !== null) {
    assert.ok(isNonEmptyString(record.status), `${label}.status must be a string`);
  }
  if (record.inline_key !== null) {
    assertVerifyingKeyInline(record.inline_key, `${label}.inline_key`);
  }
}

function assertVerifyingKeyInline(inline, label = "verifying key inline payload") {
  assert.ok(isPlainObject(inline), `${label} must be an object`);
  assert.ok(isNonEmptyString(inline.backend), `${label}.backend must be a string`);
  assert.ok(isNonEmptyString(inline.bytes_b64), `${label}.bytes_b64 must be a string`);
}

function assertRepoAgreementSnapshot(entry, label) {
  assert.ok(entry && typeof entry === "object", `${label} must be an object`);
  assert.equal(typeof entry.id, "string", `${label}.id must be a string`);
  assert.notEqual(entry.id.length, 0, `${label}.id must not be empty`);
  assert.equal(typeof entry.initiator, "string", `${label}.initiator must be a string`);
  assert.notEqual(entry.initiator.length, 0, `${label}.initiator must not be empty`);
  assert.equal(typeof entry.counterparty, "string", `${label}.counterparty must be a string`);
  assert.notEqual(entry.counterparty.length, 0, `${label}.counterparty must not be empty`);
  if (entry.custodian !== null) {
    assert.equal(typeof entry.custodian, "string", `${label}.custodian must be a string when set`);
  }
  assertRepoLegSnapshot(entry.cashLeg, `${label}.cashLeg`);
  assertRepoLegSnapshot(entry.collateralLeg, `${label}.collateralLeg`);
  assert.equal(typeof entry.rateBps, "number", `${label}.rateBps must be a number`);
  assert.ok(Number.isFinite(entry.rateBps), `${label}.rateBps must be finite`);
  assertNonNegativeInteger(entry.maturityTimestampMs, `${label}.maturityTimestampMs`);
  assertNonNegativeInteger(entry.initiatedTimestampMs, `${label}.initiatedTimestampMs`);
  assertNonNegativeInteger(entry.lastMarginCheckTimestampMs, `${label}.lastMarginCheckTimestampMs`);
  assertRepoGovernanceSnapshot(entry.governance, `${label}.governance`);
}

function assertRepoLegSnapshot(leg, label) {
  assert.ok(leg && typeof leg === "object", `${label} must be an object`);
  assert.equal(
    typeof leg.assetDefinitionId,
    "string",
    `${label}.assetDefinitionId must be a string`,
  );
  assert.notEqual(
    leg.assetDefinitionId.length,
    0,
    `${label}.assetDefinitionId must not be empty`,
  );
  assert.equal(typeof leg.quantity, "string", `${label}.quantity must be a string`);
  assert.notEqual(leg.quantity.length, 0, `${label}.quantity must not be empty`);
}

function assertRepoGovernanceSnapshot(governance, label) {
  assert.ok(governance && typeof governance === "object", `${label} must be an object`);
  assert.equal(typeof governance.haircutBps, "number", `${label}.haircutBps must be a number`);
  assert.ok(Number.isFinite(governance.haircutBps), `${label}.haircutBps must be finite`);
  assertNonNegativeInteger(governance.marginFrequencySecs, `${label}.marginFrequencySecs`);
  assert.equal(
    typeof governance.allowEarlyRepayment,
    "boolean",
    `${label}.allowEarlyRepayment must be a boolean`,
  );
}

function assertContractInstanceListResponse(page, expectedNamespace = null) {
  assert.ok(page && typeof page === "object", "contract instance page must be an object");
  assert.equal(typeof page.namespace, "string", "contract instance page namespace must be a string");
  if (expectedNamespace) {
    assert.equal(
      page.namespace,
      expectedNamespace,
      "contract instance page should echo namespace",
    );
  }
  assertNonNegativeInteger(page.total, "contract instance page total");
  assertNonNegativeInteger(page.offset, "contract instance page offset");
  assertNonNegativeInteger(page.limit, "contract instance page limit");
  assert.ok(
    Array.isArray(page.instances),
    "contract instance page must include an instances array",
  );
  page.instances.forEach((instance, index) => {
    assertContractInstanceRecord(instance, `contract instance ${index}`);
  });
}

function assertContractInstanceRecord(record, label = "contract instance record") {
  assert.ok(record && typeof record === "object", `${label} must be an object`);
  assert.equal(
    typeof record.contract_address,
    "string",
    `${label}.contract_address must be a string`,
  );
  assert.notEqual(
    record.contract_address.length,
    0,
    `${label}.contract_address must not be empty`,
  );
  assertHexString(record.code_hash_hex, `${label}.code_hash_hex`);
}

function assertAttachmentMetadata(entry, label) {
  assert.ok(entry && typeof entry === "object", `${label} must be an object`);
  assert.ok(
    typeof entry.id === "string" && entry.id.length > 0,
    `${label}.id must be a non-empty string`,
  );
  assert.ok(
    typeof entry.contentType === "string" && entry.contentType.length > 0,
    `${label}.contentType must be a non-empty string`,
  );
  assertNonNegativeInteger(entry.size, `${label}.size`);
  assertNonNegativeInteger(entry.createdMs, `${label}.createdMs`);
  if (entry.tenant !== undefined && entry.tenant !== null) {
    assert.equal(typeof entry.tenant, "string", `${label}.tenant must be a string when present`);
  }
}

function assertTriggerRecord(record, label) {
  assert.ok(record && typeof record === "object", `${label} must be an object`);
  assert.equal(typeof record.id, "string", `${label}.id must be a string`);
  assert.notEqual(record.id.length, 0, `${label}.id must not be empty`);
  assert.ok(
    record.action && typeof record.action === "object" && !Array.isArray(record.action),
    `${label}.action must be an object`,
  );
  if (record.metadata !== undefined && record.metadata !== null) {
    assert.ok(
      typeof record.metadata === "object" && !Array.isArray(record.metadata),
      `${label}.metadata must be an object when present`,
    );
  }
}

function assertHexString(value, label) {
  assert.equal(typeof value, "string", `${label} must be a string`);
  assert.notEqual(value.length, 0, `${label} must not be empty`);
  assert.ok(/^[0-9a-f]+$/i.test(value), `${label} must be hexadecimal`);
}

function assertNumberLike(value, label) {
  const isNumericString =
    typeof value === "string" && value.trim().length > 0 && Number.isFinite(Number(value));
  if (
    typeof value === "number" ||
    typeof value === "bigint" ||
    isNumericString
  ) {
    return;
  }
  throw new Error(`${label} must be numeric`);
}

function assertNonNegativeNumber(value, label) {
  assert.equal(typeof value, "number", `${label} must be a number`);
  assert.ok(Number.isFinite(value), `${label} must be finite`);
  assert.ok(value >= 0, `${label} must be non-negative`);
}

function assertEvidenceU64(value, label) {
  const integer = typeof value === "bigint" ? value : BigInt(value);
  assert.ok(integer >= 0n && integer <= 0xffffffffffffffffn, `${label} must be a u64`);
}

function assertEvidenceRecord(envelope) {
  assert.ok(envelope && typeof envelope === "object", "evidence envelope must be an object");
  assert.deepEqual(Object.keys(envelope).sort(), ["kind", "value"]);
  assert.ok(["NativeSumeragiEvidence", "SccpForgeryEvidence"].includes(envelope.kind));
  if (envelope.kind === "SccpForgeryEvidence") {
    assertSccpEvidenceRecord(envelope.value);
    return;
  }
  assert.equal(envelope.kind, "NativeSumeragiEvidence");
  const entry = envelope.value;
  assert.ok(entry && typeof entry === "object", "evidence entry must be an object");
  assert.deepEqual(Object.keys(entry).sort(), [
    "authority_generation",
    "class",
    "consensus_admitted_height",
    "context_id",
    "epoch",
    "height",
    "instance",
    "native_frame_hash",
    "offenders",
    "penalty_status",
    "recorded_height",
    "recorded_ms",
    "recorded_view",
    "safety_violation",
    "scope",
  ]);
  assert.deepEqual(Object.keys(entry.scope).sort(), ["kind", "value"]);
  assert.ok(["root", "lane"].includes(entry.scope.kind));
  if (entry.scope.kind === "root") {
    assert.equal(entry.scope.value, null);
  } else {
    assert.deepEqual(Object.keys(entry.scope.value).sort(), [
      "admission_parent_core_hash", "admission_parent_hash", "admission_parent_height",
      "admission_parent_result", "created_at", "incarnation", "lane",
    ]);
    assert.ok(Number.isInteger(entry.scope.value.lane) && entry.scope.value.lane >= 0 && entry.scope.value.lane <= 0xffffffff);
    for (const field of ["incarnation", "admission_parent_core_hash", "admission_parent_result"]) {
      assert.match(entry.scope.value[field], /^[0-9A-Fa-f]{64}$/u);
    }
    assert.match(entry.scope.value.admission_parent_hash, /^hash:[0-9A-F]{64}#[0-9A-F]{4}$/u);
    assertEvidenceU64(entry.scope.value.created_at, "lane created_at");
    assertEvidenceU64(entry.scope.value.admission_parent_height, "lane admission_parent_height");
  }
  assert.ok(["proposal", "phase_vote", "timeout_vote", "invalid_proposal", "conflicting_certificates"].includes(entry.class));
  assertEvidenceU64(entry.height, "native evidence height");
  assertEvidenceU64(entry.epoch, "native evidence epoch");
  for (const field of ["instance", "context_id", "authority_generation", "native_frame_hash"]) {
    assert.match(entry[field], /^[0-9a-f]{64}$/u);
  }
  assert.equal(typeof entry.safety_violation, "boolean");
  assert.ok(Array.isArray(entry.offenders) && entry.offenders.length <= 1024);
  assert.ok(entry.offenders.length > 0 ||
    (entry.class === "conflicting_certificates" && entry.safety_violation === true));
  let previous = -1;
  const peers = new Set();
  for (const offender of entry.offenders) {
    assert.deepEqual(Object.keys(offender).sort(), ["peer_id", "signer"]);
    assert.ok(Number.isInteger(offender.signer) && offender.signer > previous && offender.signer < 1024);
    assert.match(offender.peer_id, /^ea0130[0-9A-F]{96}$/u);
    assert.ok(!peers.has(offender.peer_id));
    peers.add(offender.peer_id);
    previous = offender.signer;
  }
  assertEvidenceU64(
    entry.recorded_height,
    "evidence entry recorded_height",
  );
  assertEvidenceU64(
    entry.recorded_view,
    "evidence entry recorded_view",
  );
  assertEvidenceU64(entry.recorded_ms, "evidence entry recorded_ms");
  assertEvidenceU64(
    entry.consensus_admitted_height,
    "evidence entry consensus_admitted_height",
  );
  assert.deepEqual(Object.keys(entry.penalty_status).sort(), ["details", "status"]);
  if (entry.penalty_status.status === "pending") {
    assert.equal(entry.penalty_status.details, null);
  } else {
    assert.equal(entry.penalty_status.status, "applied");
    assert.deepEqual(Object.keys(entry.penalty_status.details), ["height"]);
    assertEvidenceU64(
      entry.penalty_status.details.height,
      "evidence penalty height",
    );
  }
}


function assertSccpEvidenceRecord(entry) {
  assert.deepEqual(Object.keys(entry).sort(), [
    "attribution", "consensus_admitted_height", "penalty_status", "record",
    "recorded_height", "recorded_ms", "recorded_view",
  ]);
  const { record, attribution } = entry;
  assert.deepEqual(Object.keys(record).sort(), ["evidence", "generation", "offenders", "rule", "start_height"]);
  assert.deepEqual(Object.keys(record.evidence).sort(), ["aggregate_signature", "anchor", "header", "qc"]);
  assert.match(record.evidence.qc, /^[0-9A-Fa-f]{232}$/u);
  assert.match(record.evidence.header, /^[0-9A-Fa-f]{442}$/u);
  assert.match(record.evidence.aggregate_signature, /^[0-9A-Fa-f]{192}$/u);
  if (record.evidence.anchor !== null) {
    assert.deepEqual(Object.keys(record.evidence.anchor).sort(), ["core_hash", "path", "result"]);
    assert.match(record.evidence.anchor.core_hash, /^[0-9A-Fa-f]{64}$/u);
    assert.match(record.evidence.anchor.result, /^[0-9A-Fa-f]{64}$/u);
    assert.equal(record.evidence.anchor.path.length, 12);
    for (const sibling of record.evidence.anchor.path) assert.match(sibling, /^[0-9A-Fa-f]{64}$/u);
  }
  assert.deepEqual(Object.keys(record.rule).sort(), ["detail", "rule"]);
  assert.ok(["E1", "E2", "E3", "E4"].includes(record.rule.rule));
  assert.equal(record.rule.detail, null);
  assertEvidenceU64(record.generation, "SCCP generation");
  assertEvidenceU64(record.start_height, "SCCP liability start");
  assert.ok(BigInt(record.generation) > 0n && BigInt(record.start_height) > 0n);
  assert.deepEqual(Object.keys(attribution).sort(), [
    "authority_generation", "context_id", "epoch", "height", "instance", "offenders", "safety_violation", "scope",
  ]);
  assert.deepEqual(attribution.scope, { kind: "sccp_generation", value: { generation: record.generation } });
  assert.equal(attribution.height, record.start_height);
  assertEvidenceU64(attribution.epoch, "SCCP claimed epoch");
  for (const field of ["instance", "context_id", "authority_generation"]) assert.match(attribution[field], /^[0-9A-Fa-f]{64}$/u);
  assert.equal(typeof attribution.safety_violation, "boolean");
  assert.ok(record.offenders.length > 0 && record.offenders.length <= 31);
  assert.equal(attribution.offenders.length, record.offenders.length);
  let previous = -1;
  const registrations = new Set();
  for (const [index, offender] of record.offenders.entries()) {
    assert.deepEqual(Object.keys(offender).sort(), ["activation_height", "lane_id", "signer", "validator"]);
    assert.ok(Number.isInteger(offender.signer) && offender.signer > previous && offender.signer < 31);
    previous = offender.signer;
    assert.ok(Number.isInteger(offender.lane_id) && offender.lane_id >= 0 && offender.lane_id <= 0xffffffff);
    assert.equal(typeof offender.validator, "string");
    const registration = `${offender.lane_id}:${offender.validator}`;
    assert.ok(!registrations.has(registration));
    registrations.add(registration);
    assertEvidenceU64(offender.activation_height, "SCCP registration activation");
    assert.ok(BigInt(offender.activation_height) > 0n && BigInt(offender.activation_height) <= BigInt(record.start_height));
    const peer = attribution.offenders[index];
    assert.deepEqual(Object.keys(peer).sort(), ["lane_stake", "peer_id", "signer"]);
    assert.equal(peer.signer, offender.signer);
    assert.match(peer.peer_id, /^ea0130[0-9A-F]{96}$/u);
    assert.equal(peer.lane_stake, null);
  }
  for (const field of ["recorded_height", "recorded_view", "recorded_ms", "consensus_admitted_height"]) {
    assertEvidenceU64(entry[field], `SCCP evidence ${field}`);
  }
  assert.deepEqual(Object.keys(entry.penalty_status).sort(), ["details", "status"]);
  if (entry.penalty_status.status === "pending") {
    assert.equal(entry.penalty_status.details, null);
  } else {
    assert.equal(entry.penalty_status.status, "applied");
    assert.deepEqual(Object.keys(entry.penalty_status.details), ["height"]);
    assertEvidenceU64(entry.penalty_status.details.height, "SCCP penalty height");
  }
}
