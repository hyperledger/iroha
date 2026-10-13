import { test as baseTest } from "node:test";
import assert from "node:assert/strict";
import { ed25519 } from "@noble/curves/ed25519";

import { AccountAddress } from "../src/address.js";
import { planDomainLease, SNS_DOMAIN_SUFFIX_ID } from "../src/domainLease.js";
import {
  buildGrantAssetDefinitionAliasScopeInstruction,
} from "../src/instructionBuilders.js";
import { NetworkId } from "../src/networkId.js";
import {
  noritoDecodeInstructionBoxArchive,
  noritoEncodeInstructionBoxArchive,
} from "../src/norito.js";
import { createTairaLocalSigningContext } from "../src/tairaTestnetProfile.js";
import { LocalSigningContext, ToriiClient } from "../src/toriiClient.js";
import { buildTransactionPayload } from "../src/transaction.js";
import { makeNativeTest } from "./helpers/native.js";

const test = makeNativeTest(baseTest, {
  require: ["instructionJsonFromWirePair", "noritoEncodeInstructionBoxArchive"],
});

const PREFIX = 369;
const NETWORK_ID = NetworkId.parse(
  "hash:5C3E66C94E079079FF4FC46F59810B9C4EC7B2646DD45CE937831C0FDCE20C9B#44D9",
);
const XOR = "6TEAJqbb8oEPmLncoNiMRbLEK6tw";
const OWNER_KEY = new Uint8Array(32).fill(0x31);
const OWNER = AccountAddress.fromAccount({
  publicKey: ed25519.getPublicKey(OWNER_KEY),
  algorithm: "ed25519",
}).toI105(PREFIX);

/** Live Taira `GET /v1/sns/policies/4098` shape (2026-10-13). */
const DOMAIN_POLICY = {
  suffix_id: SNS_DOMAIN_SUFFIX_ID,
  suffix: "domain",
  steward: OWNER,
  status: { status: "Active", detail: null },
  min_term_years: 1,
  max_term_years: 5,
  grace_period_days: 30,
  redemption_period_days: 60,
  referral_cap_bps: 0,
  reserved_labels: [],
  payment_asset_id: XOR,
  pricing: [
    {
      tier_id: 0,
      label_regex: "^[a-z0-9-]{1,63}\\.[a-z0-9-]{1,63}$",
      base_price: { asset_id: XOR, amount: "0.5" },
      auction_kind: { kind: "VickreyCommitReveal", detail: null },
      dutch_floor: null,
      min_duration_years: 1,
      max_duration_years: 5,
    },
  ],
  fee_split: { treasury_bps: 7000, steward_bps: 3000, referral_max_bps: 0, escrow_bps: 0 },
  fund_splitter_account: OWNER,
  policy_version: 1,
  metadata: {},
};

/** Extract the bare framed concrete payload from an `InstructionBox` archive. */
function wireFrame(instruction) {
  const archive = Buffer.from(noritoEncodeInstructionBoxArchive(instruction, PREFIX));
  const varint = (offset) => {
    let value = 0;
    let shift = 0;
    let cursor = offset;
    for (;;) {
      const byte = archive[cursor];
      cursor += 1;
      value += (byte & 0x7f) * 2 ** shift;
      if ((byte & 0x80) === 0) return [value, cursor];
      shift += 7;
    }
  };
  const [nameLength, nameStart] = varint(0);
  const [payloadLength, payloadStart] = varint(nameStart + nameLength);
  const payloadField = archive.subarray(payloadStart, payloadStart + payloadLength);
  return payloadField.subarray(8, 8 + Number(payloadField.readBigUInt64LE(0)));
}

function json(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function plannerClient(onPlan) {
  const requests = [];
  const client = new ToriiClient("https://taira.example", {
    localSigningContext: new LocalSigningContext(NETWORK_ID, PREFIX),
    fetchImpl: async (url, init) => {
      const path = new URL(url).pathname;
      requests.push({ path, init });
      if (path === `/v1/sns/policies/${SNS_DOMAIN_SUFFIX_ID}`) return json(200, DOMAIN_POLICY);
      if (path === "/v1/aliases/setup/plan") return json(200, onPlan(JSON.parse(init.body), init));
      return json(404, { code: "not_found", message: path });
    },
  });
  return { client, requests };
}

test("planDomainLease quotes one EnsureAlias and returns verified instruction JSON", async () => {
  const { client, requests } = plannerClient((request) => {
    const [intent] = request.intents;
    return {
      body: {
        version: 1,
        authority: OWNER,
        network_id: NETWORK_ID.toString(),
        anchor: { block_height: 10, block_hash: "ab".repeat(32) },
        resources: [
          {
            intent: intent.intent,
            disposition: { kind: "create", value: null },
            quote: { exact_amount: "1", guard: intent.quote_guard },
            instruction_index: 0,
          },
        ],
        instructions: [
          { wire_id: "iroha.alias.ensure", framed_payload: [...wireFrame({ EnsureAlias: intent })] },
        ],
        totals_by_asset: [{ payment_asset: XOR, amount: "1" }],
        warnings: [],
        blockers: [],
        valid_until_ms: intent.quote_guard.valid_until_ms,
      },
      plan_hash: "cd".repeat(32),
    };
  });
  const before = Date.now();
  const plan = await planDomainLease(
    client,
    { owner: OWNER, domain: "BondPoc.universal", years: 2 },
    { canonicalAuth: { accountId: OWNER, privateKey: OWNER_KEY } },
  );
  const planRequest = requests.find(({ path }) => path === "/v1/aliases/setup/plan");
  assert.ok(planRequest.init.headers["X-Iroha-Signature"] ?? planRequest.init.headers.get?.("X-Iroha-Signature"));
  const sent = JSON.parse(planRequest.init.body);
  assert.equal(sent.schema_version, 1);
  assert.deepEqual(sent.intents[0].intent, {
    kind: "domain",
    intent: { domain: { canonical_name: "bondpoc.universal", dataspace_id: 0 }, owner: OWNER },
  });
  assert.deepEqual(sent.intents[0].acquisition, { term_years: 2, pricing_class_hint: null });
  assert.equal(sent.intents[0].quote_guard.max_amount, "1");
  assert.equal(sent.intents[0].quote_guard.expected_policy_version, 1);
  assert.equal(sent.intents[0].quote_guard.expected_payment_asset, XOR);
  assert.ok(sent.intents[0].quote_guard.valid_until_ms >= before + 5 * 60 * 1000);

  assert.equal(plan.disposition, "create");
  assert.equal(plan.instructions.length, 1);
  assert.deepEqual(plan.instructions[0], { EnsureAlias: sent.intents[0] });
  assert.deepEqual(
    noritoDecodeInstructionBoxArchive(
      noritoEncodeInstructionBoxArchive(plan.instructions[0], PREFIX),
      PREFIX,
    ),
    plan.instructions[0],
  );
  assert.deepEqual(plan.totalsByAsset, [{ payment_asset: XOR, amount: "1" }]);
  const draft = buildTransactionPayload({
    networkId: NETWORK_ID,
    authority: OWNER,
    instructions: [
      ...plan.instructions,
      buildGrantAssetDefinitionAliasScopeInstruction({ grantee: OWNER, domainId: "bondpoc.universal" }),
    ],
    feePayment: { payer: "authority", chargeLimits: [] },
    creationTimeMs: 1_700_000_000_000,
    ttlMs: 30_000,
    nonce: 1,
  });
  assert.equal(draft.payload.instructions.Instructions.length, 2);
});

test("planDomainLease rejects substituted planner frames and blocked plans", async () => {
  const substituted = plannerClient((request) => {
    const changed = structuredClone(request.intents[0]);
    changed.quote_guard.max_amount = "100";
    return {
      body: {
        authority: OWNER,
        resources: [{ disposition: { kind: "create", value: null }, quote: null }],
        instructions: [{ wire_id: "iroha.alias.ensure", framed_payload: [...wireFrame({ EnsureAlias: changed })] }],
        blockers: [],
        valid_until_ms: 1,
      },
      plan_hash: "00",
    };
  });
  await assert.rejects(
    planDomainLease(
      substituted.client,
      { owner: OWNER, domain: "bondpoc.universal", years: 1 },
      { canonicalAuth: { accountId: OWNER, privateKey: OWNER_KEY } },
    ),
    /differs from the requested domain lease/u,
  );
  const blocked = plannerClient(() => ({
    body: { resources: [], instructions: [], blockers: [{ code: "size" }] },
    plan_hash: "00",
  }));
  await assert.rejects(
    planDomainLease(
      blocked.client,
      { owner: OWNER, domain: "bondpoc.universal", years: 1 },
      { canonicalAuth: { accountId: OWNER, privateKey: OWNER_KEY } },
    ),
    /blocked/u,
  );
  await assert.rejects(
    planDomainLease(
      blocked.client,
      { owner: OWNER, domain: "bondpoc.universal", years: 6 },
      { canonicalAuth: { accountId: OWNER, privateKey: OWNER_KEY } },
    ),
    /1\.\.=5/u,
  );
  await assert.rejects(
    planDomainLease(
      blocked.client,
      { owner: OWNER, domain: "bondpoc.bank", years: 1 },
      { canonicalAuth: { accountId: OWNER, privateKey: OWNER_KEY } },
    ),
    /dataspaceId is required/u,
  );
  const unauthenticated = new ToriiClient("https://taira.example", {
    localSigningContext: createTairaLocalSigningContext(NETWORK_ID),
    fetchImpl: async () => json(200, DOMAIN_POLICY),
  });
  await assert.rejects(
    planDomainLease(unauthenticated, { owner: OWNER, domain: "bondpoc.universal", years: 1 }, {}),
    /requires canonicalAuth/u,
  );
});
