import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";

import {
  AccountAddress,
  LocalSigningContext,
  NetworkId,
  ToriiClient as BaseToriiClient,
  canonicalRequestSignatureMessage,
  generateKeyPair,
  verifyEd25519,
} from "../src/index.js";
import { isExactJsonMediaType } from "../src/toriiBoundedResponse.js";

const NETWORK_ID = NetworkId.fromBytes(Buffer.alloc(32, 0xa5));
const LOCAL_SIGNING_CONTEXT = new LocalSigningContext(NETWORK_ID, 753);

class ToriiClient extends BaseToriiClient {
  constructor(baseUrl, options = {}) {
    super(baseUrl, { localSigningContext: LOCAL_SIGNING_CONTEXT, ...options });
  }
}

function ed25519PublicKeyBytes() {
  const { publicKey } = generateKeyPairSync("ed25519");
  const der = publicKey.export({ format: "der", type: "spki" });
  // SPKI encoding stores the raw ed25519 key in the last 32 bytes.
  return new Uint8Array(der.subarray(der.length - 32));
}

function demoAccountId() {
  const address = AccountAddress.fromAccount({ publicKey: ed25519PublicKeyBytes() });
  return address.toI105();
}

const VALID_ACCOUNT_ID = demoAccountId();
const ALT_ACCOUNT_ID = demoAccountId();

function jsonResponse(status, body) {
  return new Response(body == null ? null : JSON.stringify(body), {
    status,
    headers: body == null ? undefined : { "Content-Type": "application/json" },
  });
}

test("resolveAliasByIndex enforces non-negative indices before issuing requests", async () => {
  let fetchCalls = 0;
  const client = new ToriiClient("https://example.test", {
    fetchImpl: async () => {
      fetchCalls += 1;
      return jsonResponse(200, {});
    },
  });

  await assert.rejects(
    () => client.resolveAliasByIndex(-5),
    (error) => {
      assert(error instanceof TypeError);
      assert.match(error.message, /index must be a non-negative integer/);
      return true;
    },
  );
  assert.equal(fetchCalls, 0, "validation should occur before network requests");
});

test("resolveAliasByIndex rejects non-numeric indices early", async () => {
  let fetchCalls = 0;
  const client = new ToriiClient("https://example.test", {
    fetchImpl: async () => {
      fetchCalls += 1;
      return jsonResponse(200, {});
    },
  });

  await assert.rejects(
    () => client.resolveAliasByIndex("not-a-number"),
    (error) => {
      assert(error instanceof TypeError);
      assert.match(error.message, /index must be a non-negative integer/);
      return true;
    },
  );
  assert.equal(fetchCalls, 0, "invalid indices should not trigger network calls");
});

test("resolveAlias normalises IBAN input and requires canonical alias responses", async () => {
  let lastRequest = null;
  const client = new ToriiClient("https://example.test", {
    fetchImpl: async (input, init) => {
      lastRequest = { input, init };
      assert.equal(init.method, "POST");
      const parsed = JSON.parse(init.body);
      assert.equal(
        parsed.alias,
        "DE89370400440532013000",
        "request payload should carry normalised IBAN",
      );
      return jsonResponse(200, {
        alias: "DE89370400440532013000",
        account_id: VALID_ACCOUNT_ID,
        index: 42,
        source: "runtime",
      });
    },
  });

  const result = await client.resolveAlias("de89 3704 0044 0532 0130 00");
  assert.equal(result.alias, "DE89370400440532013000");
  assert.equal(result.account_id, ToriiClient._requireAccountId(VALID_ACCOUNT_ID));
  assert.equal(result.index, 42);
  assert.equal(result.source, "runtime");
  const url = new URL(lastRequest.input);
  assert.equal(url.pathname, "/v1/aliases/resolve");
  assert.equal(lastRequest.init.headers["Content-Type"], "application/json");
});

test("resolveAlias attaches canonical auth when provided", async () => {
  const { privateKey, publicKey } = generateKeyPair({ seed: Buffer.alloc(32, 12) });
  const signerAccountAlias = "operator-1@mibank.paynet";
  let lastRequest = null;
  const fetchImpl = async (input, init) => {
    lastRequest = { input, init };
    return jsonResponse(200, {
      alias: "tidal-river-4160@mibank.paynet",
      account_id: VALID_ACCOUNT_ID,
      source: "runtime",
    });
  };
  const client = new ToriiClient("https://example.test", {
    fetchImpl,
  });

  const result = await client.resolveAlias("tidal-river-4160@mibank.paynet", {
    canonicalAuth: { accountId: signerAccountAlias, privateKey },
  });

  assert.equal(result.account_id, ToriiClient._requireAccountId(VALID_ACCOUNT_ID));
  assert.equal(lastRequest.init.headers["X-Iroha-Account"], signerAccountAlias);
  const url = new URL(lastRequest.input);
  const timestampMs = Number(lastRequest.init.headers["X-Iroha-Timestamp-Ms"]);
  const nonce = lastRequest.init.headers["X-Iroha-Nonce"];
  const message = canonicalRequestSignatureMessage({
    networkId: NETWORK_ID,
    method: lastRequest.init.method,
    path: url.pathname,
    body: lastRequest.init.body,
    timestampMs,
    nonce,
  });
  const signature = Buffer.from(lastRequest.init.headers["X-Iroha-Signature"], "base64");
  assert.equal(verifyEd25519(message, signature, publicKey), true);
});

test("resolveAlias returns null for missing aliases and rejects when runtime is unavailable", async () => {
  const client = new ToriiClient("https://example.test", {
    fetchImpl: async (_input, init) => {
      const parsed = JSON.parse(init.body);
      if (parsed.alias === "missing-alias") {
        return jsonResponse(404, {});
      }
      return jsonResponse(503, {});
    },
  });

  const missing = await client.resolveAlias("missing-alias");
  assert.equal(missing, null, "missing aliases should return null");

  await assert.rejects(
    () => client.resolveAlias("disabled-alias"),
    /ISO bridge runtime is unavailable/,
  );
});

test("resolveAliasByIndex posts payloads and requires canonical responses", async () => {
  let lastRequest = null;
  const client = new ToriiClient("https://example.test", {
    fetchImpl: async (input, init) => {
      lastRequest = { input, init };
      const parsed = JSON.parse(init.body);
      assert.equal(parsed.index, 7);
      return jsonResponse(200, {
        alias: "GB82WEST12345698765432",
        account_id: ALT_ACCOUNT_ID,
        index: 7,
        source: "imported",
      });
    },
  });

  const result = await client.resolveAliasByIndex("7");
  assert.equal(result.alias, "GB82WEST12345698765432");
  assert.equal(result.account_id, ToriiClient._requireAccountId(ALT_ACCOUNT_ID));
  assert.equal(result.index, 7);
  assert.equal(result.source, "imported");
  const url = new URL(lastRequest.input);
  assert.equal(url.pathname, "/v1/aliases/resolve-index");
  assert.equal(lastRequest.init.method, "POST");
});

test("resolveAliasByIndex forwards service errors", async () => {
  const client = new ToriiClient("https://example.test", {
    fetchImpl: async (_input, init) => {
      const parsed = JSON.parse(init.body);
      return parsed.index === 0 ? jsonResponse(404, {}) : jsonResponse(503, {});
    },
  });

  const missing = await client.resolveAliasByIndex(0);
  assert.equal(missing, null);

  await assert.rejects(
    () => client.resolveAliasByIndex(9),
    /ISO bridge runtime is unavailable/,
  );
});

test("lookupAliasesByAccount posts canonical account ids with optional filters", async () => {
  let lastRequest = null;
  const client = new ToriiClient("https://example.test", {
    fetchImpl: async (input, init) => {
      lastRequest = { input, init };
      const parsed = JSON.parse(init.body);
      assert.equal(parsed.account_id, ToriiClient._requireAccountId(VALID_ACCOUNT_ID));
      assert.equal(parsed.dataspace, "centralbank");
      assert.equal(parsed.domain, "banka");
      return jsonResponse(200, {
        account_id: VALID_ACCOUNT_ID,
        total: "1",
        items: [
          {
            alias: "merchant@banka.centralbank",
            dataspace: "centralbank",
            domain: "banka",
            is_primary: true,
          },
        ],
      });
    },
  });

  const result = await client.lookupAliasesByAccount(VALID_ACCOUNT_ID, {
    dataspace: "centralbank",
    domain: "banka",
  });
  assert.equal(result.account_id, ToriiClient._requireAccountId(VALID_ACCOUNT_ID));
  assert.equal(result.total, 1);
  assert.deepEqual(result.items, [
    {
      alias: "merchant@banka.centralbank",
      dataspace: "centralbank",
      domain: "banka",
      is_primary: true,
    },
  ]);
  const url = new URL(lastRequest.input);
  assert.equal(url.pathname, "/v1/aliases/by-account");
  assert.equal(lastRequest.init.method, "POST");
});

test("lookupAliasesByAccount returns null for missing accounts", async () => {
  const client = new ToriiClient("https://example.test", {
    fetchImpl: async () => jsonResponse(404, {}),
  });

  const result = await client.lookupAliasesByAccount(ALT_ACCOUNT_ID);
  assert.equal(result, null);
});

test("lookupAliasesByAccount validates options before issuing requests", async () => {
  let fetchCalls = 0;
  const client = new ToriiClient("https://example.test", {
    fetchImpl: async () => {
      fetchCalls += 1;
      return jsonResponse(200, {});
    },
  });

  await assert.rejects(
    () => client.lookupAliasesByAccount(VALID_ACCOUNT_ID, { unexpected: true }),
    /unsupported/i,
  );
  assert.equal(fetchCalls, 0);
});

test("lookupRetailRecipient posts canonical account and alias payloads", async () => {
  let lastRequest = null;
  const client = new ToriiClient("https://example.test", {
    fetchImpl: async (input, init) => {
      lastRequest = { input, init };
      const parsed = JSON.parse(init.body);
      assert.equal(parsed.account_id, ToriiClient._requireAccountId(VALID_ACCOUNT_ID));
      assert.equal(parsed.alias_fqn, "payee@hbl.sbp");
      return jsonResponse(200, {
        resolved: true,
        account_id: VALID_ACCOUNT_ID,
        alias_fqn: "payee@hbl.sbp",
        fi_id: "hbl.sbp",
        full_name: "Ayesha Khan",
      });
    },
  });

  const result = await client.lookupRetailRecipient({
    accountId: VALID_ACCOUNT_ID,
    aliasFqn: "payee@hbl.sbp",
  });

  assert.deepEqual(result, {
    resolved: true,
    account_id: ToriiClient._requireAccountId(VALID_ACCOUNT_ID),
    alias_fqn: "payee@hbl.sbp",
    fi_id: "hbl.sbp",
    full_name: "Ayesha Khan",
  });
  const url = new URL(lastRequest.input);
  assert.equal(url.pathname, "/v1/retail/recipients/lookup");
  assert.equal(lastRequest.init.method, "POST");
});

test("lookupRetailRecipient binds the response to the requested account and alias", async () => {
  for (const payload of [
    {
      resolved: false,
      account_id: ALT_ACCOUNT_ID,
      alias_fqn: "payee@hbl.sbp",
      fi_id: "hbl.sbp",
    },
    {
      resolved: false,
      account_id: VALID_ACCOUNT_ID,
      alias_fqn: "payee@ubl.sbp",
      fi_id: "ubl.sbp",
    },
  ]) {
    const client = new ToriiClient("https://example.test", {
      fetchImpl: async () => jsonResponse(200, payload),
    });
    await assert.rejects(
      () =>
        client.lookupRetailRecipient({
          accountId: VALID_ACCOUNT_ID,
          aliasFqn: "payee@hbl.sbp",
        }),
      /does not match the requested account and alias/i,
    );
  }
});

test("lookupRetailRecipient rejects noncanonical aliases before issuing a request", async () => {
  let fetchCalls = 0;
  const client = new ToriiClient("https://example.test", {
    fetchImpl: async () => {
      fetchCalls += 1;
      return jsonResponse(200, {});
    },
  });
  await assert.rejects(
    () =>
      client.lookupRetailRecipient({
        accountId: VALID_ACCOUNT_ID,
        aliasFqn: "Payee@hbl.sbp",
      }),
    /canonical/i,
  );
  assert.equal(fetchCalls, 0);
});

test("lookupRetailRecipient rejects conflicting request aliases", async () => {
  let fetchCalls = 0;
  const client = new ToriiClient("https://example.test", {
    fetchImpl: async () => {
      fetchCalls += 1;
      return jsonResponse(200, {});
    },
  });
  await assert.rejects(
    () =>
      client.lookupRetailRecipient({
        accountId: VALID_ACCOUNT_ID,
        account_id: ALT_ACCOUNT_ID,
        aliasFqn: "payee@hbl.sbp",
      }),
    /accountId and account_id must match/i,
  );
  await assert.rejects(
    () =>
      client.lookupRetailRecipient({
        accountId: VALID_ACCOUNT_ID,
        aliasFqn: "payee@hbl.sbp",
        alias_fqn: "other@hbl.sbp",
      }),
    /aliasFqn and alias_fqn must match/i,
  );
  assert.equal(fetchCalls, 0);
});

test("routeRetailRecipient returns the exact privacy-minimized route shape", async () => {
  let lastRequest = null;
  const client = new ToriiClient("https://example.test", {
    fetchImpl: async (input, init) => {
      lastRequest = { input, init };
      assert.deepEqual(JSON.parse(init.body), {
        account_id: ToriiClient._requireAccountId(ALT_ACCOUNT_ID),
      });
      return jsonResponse(200, {
        account_id: ALT_ACCOUNT_ID,
        alias_fqn: "payee@ubl.sbp",
        fi_id: "ubl.sbp",
      });
    },
  });

  const result = await client.routeRetailRecipient(ALT_ACCOUNT_ID);

  assert.deepEqual(result, {
    account_id: ToriiClient._requireAccountId(ALT_ACCOUNT_ID),
    alias_fqn: "payee@ubl.sbp",
    fi_id: "ubl.sbp",
  });
  assert.deepEqual(Object.keys(result).sort(), ["account_id", "alias_fqn", "fi_id"]);
  assert.equal(new URL(lastRequest.input).pathname, "/v1/retail/recipients/route");
  assert.equal(lastRequest.init.method, "POST");
});

test("routeRetailRecipient rejects noncanonical route payloads", async () => {
  for (const payload of [
    {
      account_id: ALT_ACCOUNT_ID,
      alias_fqn: "Payee@ubl.sbp",
      fi_id: "ubl.sbp",
    },
    {
      account_id: ALT_ACCOUNT_ID,
      alias_fqn: "payee@ubl.sbp",
      fi_id: "ubl.sbp",
      extra: true,
    },
  ]) {
    const client = new ToriiClient("https://example.test", {
      fetchImpl: async () => jsonResponse(200, payload),
    });
    await assert.rejects(() => client.routeRetailRecipient(ALT_ACCOUNT_ID), /canonical|unsupported/i);
  }
});

test("routeRetailRecipient binds the response to the requested account", async () => {
  const client = new ToriiClient("https://example.test", {
    fetchImpl: async () =>
      jsonResponse(200, {
        account_id: VALID_ACCOUNT_ID,
        alias_fqn: "payee@ubl.sbp",
        fi_id: "ubl.sbp",
      }),
  });
  await assert.rejects(
    () => client.routeRetailRecipient(ALT_ACCOUNT_ID),
    /does not match the requested account/i,
  );
});

test("findFeeSponsorProgramById binds controller identity and exact program name", async () => {
  const sponsor = ToriiClient._requireAccountId(VALID_ACCOUNT_ID);
  const responseSponsor = AccountAddress.parseEncoded(sponsor).address.toI105(42);
  const programId = `${sponsor}/wallet_fx`;
  const program = {
    id: { sponsor: responseSponsor, name: "wallet_fx" },
    payout_account: sponsor,
    lifecycle: { state: "active", value: null },
    active_revision: 7,
  };
  let lastRequest = null;
  const client = new ToriiClient("https://example.test", {
    fetchImpl: async (input, init) => {
      lastRequest = { input, init };
      assert.deepEqual(JSON.parse(init.body), { program_id: programId });
      return jsonResponse(200, program);
    },
  });
  const result = await client.findFeeSponsorProgramById(programId, {
    canonicalAuth: { accountId: sponsor, privateKey: Buffer.alloc(32, 12) },
  });
  assert.deepEqual(result, program);
  assert.equal(new URL(lastRequest.input).pathname, "/v1/fee-sponsor-programs/by-id");
  assert.equal(lastRequest.init.method, "POST");
});

test("findFeeSponsorProgramById returns null and rejects mismatched lifecycle records", async () => {
  const sponsor = ToriiClient._requireAccountId(VALID_ACCOUNT_ID);
  const canonicalAuth = { accountId: sponsor, privateKey: Buffer.alloc(32, 13) };
  const absent = new ToriiClient("https://example.test", {
    fetchImpl: async () => jsonResponse(404, {}),
  });
  assert.equal(
    await absent.findFeeSponsorProgramById(`${sponsor}/wallet_fx`, { canonicalAuth }),
    null,
  );

  for (const id of [
    { sponsor, name: "other" },
    { sponsor: ALT_ACCOUNT_ID, name: "wallet_fx" },
  ]) {
    const mismatched = new ToriiClient("https://example.test", {
      fetchImpl: async () =>
        jsonResponse(200, {
          id,
          payout_account: sponsor,
          lifecycle: { state: "active", value: null },
          active_revision: 1,
        }),
    });
    await assert.rejects(
      () => mismatched.findFeeSponsorProgramById(`${sponsor}/wallet_fx`, { canonicalAuth }),
      /does not match the requested exact program id/i,
    );
  }
});

test("findFeeSponsorProgramById rejects noncanonical names and optional lifecycle values", async () => {
  const sponsor = ToriiClient._requireAccountId(VALID_ACCOUNT_ID);
  const canonicalAuth = { accountId: sponsor, privateKey: Buffer.alloc(32, 15) };
  const permittedFormatName = "wallet\u200b\u2060\ufeff\u00ad";
  const permittedClient = new ToriiClient("https://example.test", {
    fetchImpl: async () => jsonResponse(200, {
      id: { sponsor, name: permittedFormatName },
      payout_account: sponsor,
      lifecycle: { state: "active", value: null },
    }),
  });
  await assert.doesNotReject(() => permittedClient.findFeeSponsorProgramById(
    `${sponsor}/${permittedFormatName}`,
    { canonicalAuth },
  ));

  for (const name of ["x".repeat(256), "wallet\u0091", "wallet\u202e", "wallet\ud800"]) {
    const client = new ToriiClient("https://example.test", {
      fetchImpl: async () => {
        throw new Error("noncanonical request must fail before dispatch");
      },
    });
    await assert.rejects(
      () => client.findFeeSponsorProgramById(`${sponsor}/${name}`, { canonicalAuth }),
      /canonical Iroha Name/i,
    );
  }

  const invalidRecords = [
    { active_revision: null },
    { staged_revision: null },
    { scheduled_activation: null },
    { scheduled_activation: { revision: 1, activate_at_height: 0 } },
    { id: { sponsor, name: "wallet\u202e" } },
  ];
  for (const mutation of invalidRecords) {
    const program = {
      id: { sponsor, name: "wallet_fx" },
      payout_account: sponsor,
      lifecycle: { state: "active", value: null },
      ...mutation,
    };
    const client = new ToriiClient("https://example.test", {
      fetchImpl: async () => jsonResponse(200, program),
    });
    await assert.rejects(
      () => client.findFeeSponsorProgramById(`${sponsor}/wallet_fx`, { canonicalAuth }),
      /canonical|positive|omitted|exact object/i,
    );
  }
});

test("findFeeSponsorProgramById enforces its strict 64 KiB transport boundary", async () => {
  const sponsor = ToriiClient._requireAccountId(VALID_ACCOUNT_ID);
  const programId = `${sponsor}/wallet_fx`;
  const canonicalAuth = { accountId: sponsor, privateKey: Buffer.alloc(32, 16) };
  const program = {
    id: { sponsor, name: "wallet_fx" },
    payout_account: sponsor,
    lifecycle: { state: "active", value: null },
    active_revision: 1,
  };
  const encoded = JSON.stringify(program);
  const encodedBytes = Buffer.from(encoded, "utf8");
  const exact = Buffer.concat([
    encodedBytes,
    Buffer.alloc(65_536 - encodedBytes.length, 0x20),
  ]);
  const exactClient = new ToriiClient("https://example.test", {
    fetchImpl: async () => new Response(exact, {
      status: 200,
      headers: { "Content-Type": "application/json; charset=utf-8" },
    }),
  });
  assert.deepEqual(
    await exactClient.findFeeSponsorProgramById(programId, { canonicalAuth }),
    program,
  );

  for (const status of [200, 404, 503]) {
    const oversized = new ToriiClient("https://example.test", {
      fetchImpl: async () => new Response(Buffer.alloc(65_537, 0x20), {
        status,
        headers: { "Content-Type": "application/json" },
      }),
    });
    await assert.rejects(
      () => oversized.findFeeSponsorProgramById(programId, { canonicalAuth }),
      /65536-byte/u,
    );
  }

  const duplicate = encoded.replace(
    '"active_revision":1',
    '"active_revision":1,"active_revision":2',
  );
  const malformedBodies = [
    new Response(duplicate, {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }),
    new Response(Uint8Array.from([0x7b, 0x22, 0x78, 0x22, 0x3a, 0xff, 0x7d]), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }),
    new Response(encoded, {
      status: 200,
      headers: { "Content-Type": "application/json, application/json" },
    }),

    new Response(encoded, {
      status: 200,
      headers: { "Content-Type": "application/json;" },
    }),
    new Response(encoded, {
      status: 200,
      headers: { "Content-Type": "application/json; charset" },
    }),
  ];
  for (const response of malformedBodies) {
    const client = new ToriiClient("https://example.test", {
      fetchImpl: async () => response,
    });
    await assert.rejects(
      () => client.findFeeSponsorProgramById(programId, { canonicalAuth }),
      /duplicate object key|valid UTF-8|application\/json media type/u,
    );
  }
  for (const confusable of ["application/jſon", "applıcation/json", "applİcation/json"]) {
    assert.equal(isExactJsonMediaType(confusable), false);
  }

  for (const contentType of [
    'Application/JSON; charset="utf-8"; note="é"',
    'application/json; profile="a,b"',
  ]) {
    const parameterized = new ToriiClient("https://example.test", {
      fetchImpl: async () => new Response(encoded, {
        status: 200,
        headers: { "Content-Type": contentType },
      }),
    });
    assert.deepEqual(
      await parameterized.findFeeSponsorProgramById(programId, { canonicalAuth }),
      program,
    );
  }

  const quotedRevision = new ToriiClient("https://example.test", {
    fetchImpl: async () => new Response(
      encoded.replace('"active_revision":1', '"active_revision":"1"'),
      { status: 200, headers: { "Content-Type": "application/json" } },
    ),
  });
  await assert.rejects(
    () => quotedRevision.findFeeSponsorProgramById(programId, { canonicalAuth }),
    /canonical unsigned integer/u,
  );

  const maximumU64 = new ToriiClient("https://example.test", {
    fetchImpl: async () => new Response(
      encoded.replace('"active_revision":1', '"active_revision":18446744073709551615'),
      { status: 200, headers: { "Content-Type": "application/json" } },
    ),
  });
  const maximumProgram = await maximumU64.findFeeSponsorProgramById(
    programId,
    { canonicalAuth },
  );
  assert.equal(maximumProgram.active_revision, 18_446_744_073_709_551_615n);

  const overflowU64 = new ToriiClient("https://example.test", {
    fetchImpl: async () => new Response(
      encoded.replace('"active_revision":1', '"active_revision":18446744073709551616'),
      { status: 200, headers: { "Content-Type": "application/json" } },
    ),
  });
  await assert.rejects(
    () => overflowU64.findFeeSponsorProgramById(programId, { canonicalAuth }),
    /between 0 and 18446744073709551615/u,
  );
});

test("quoteFees account-signs an exact non-default-network draft and returns typed limits", async () => {
  const parsedAuthority = AccountAddress.parseEncoded(
    ToriiClient._requireAccountId(VALID_ACCOUNT_ID),
  );
  const authority = parsedAuthority.address.toI105(369);
  const assetDefinitionId = "66owaQmAQMuHxPzxUN3bqZ6FJfDa";
  const payload = {
    chain: "test-chain",
    authority,
    fee_payment: {
      payer: "authority",
      value: { charge_limits: [], gas_limit: null },
    },
  };
  const quote = {
    intent: {
      payer: "authority",
      value: {
        charge_limits: [
          {
            kind: { kind: "nexus", value: null },
            asset_definition_id: assetDefinitionId,
            max_amount: "2.5",
          },
        ],
        gas_limit: null,
      },
    },
    observation: {
      ledger_time_ms: 100,
      next_block_height: 9,
      route_dataspace_id: 0,
    },
    components: [
      {
        kind: { kind: "nexus", value: null },
        asset_definition_id: assetDefinitionId,
        max_amount: "2.5",
      },
    ],
    capacities: [],
    decision: {
      status: "accepted",
      value: {
        debit_source: { kind: "account", value: authority },
        program_revision: null,
      },
    },
  };
  let lastRequest = null;
  const client = new ToriiClient("https://example.test", {
    fetchImpl: async (input, init) => {
      lastRequest = { input, init };
      return jsonResponse(200, quote);
    },
  });
  const result = await client.quoteFees({ payload }, {
    canonicalAuth: { accountId: authority, privateKey: Buffer.alloc(32, 14) },
  });
  assert.deepEqual(result, quote);
  assert.deepEqual(JSON.parse(lastRequest.init.body), { payload });
  assert.equal(new URL(lastRequest.input).pathname, "/v1/fees/quote");
});

test("quoteFees compares I105 displays by controller identity and permits exact alias auth", async () => {
  const parsedAuthority = AccountAddress.parseEncoded(VALID_ACCOUNT_ID);
  const authority = parsedAuthority.address.toI105(369);
  const alternateDisplay = parsedAuthority.address.toI105(753);
  const payload = {
    authority,
    fee_payment: {
      payer: "authority",
      value: { charge_limits: [], gas_limit: null },
    },
  };
  const quote = {
    intent: payload.fee_payment,
    observation: {
      ledger_time_ms: 1,
      next_block_height: 1,
      route_dataspace_id: 0,
    },
    components: [],
    capacities: [],
    decision: {
      status: "accepted",
      value: {
        debit_source: { kind: "account", value: alternateDisplay },
        program_revision: null,
      },
    },
  };
  let fetchCalls = 0;
  const accountHeaders = [];
  const client = new ToriiClient("https://example.test", {
    fetchImpl: async (_input, init) => {
      fetchCalls += 1;
      accountHeaders.push(new Headers(init.headers).get("X-Iroha-Account"));
      return jsonResponse(200, quote);
    },
  });

  assert.deepEqual(
    await client.quoteFees({ payload }, {
      canonicalAuth: {
        accountId: alternateDisplay,
        privateKey: Buffer.alloc(32, 19),
      },
    }),
    quote,
  );
  assert.deepEqual(
    await client.quoteFees({ payload }, {
      canonicalAuth: {
        accountId: "payer@taira",
        privateKey: Buffer.alloc(32, 20),
      },
    }),
    quote,
  );
  assert.equal(fetchCalls, 2);
  assert.equal(accountHeaders[1], "payer@taira");
});

test("quoteFees rejects duplicate response keys before semantic decoding", async () => {
  const authority = AccountAddress.parseEncoded(VALID_ACCOUNT_ID).address.toI105(369);
  const payload = {
    authority,
    fee_payment: {
      payer: "authority",
      value: { charge_limits: [], gas_limit: null },
    },
  };
  const responseText = JSON.stringify({
    intent: payload.fee_payment,
    observation: {
      ledger_time_ms: 1,
      next_block_height: 1,
      route_dataspace_id: 0,
    },
    components: [],
    capacities: [],
    decision: {
      status: "accepted",
      value: {
        debit_source: { kind: "account", value: authority },
        program_revision: null,
      },
    },
  }).replace(
    '"program_revision":null',
    '"program_revision":null,"program_revision":null',
  );
  const client = new ToriiClient("https://example.test", {
    fetchImpl: async () => new Response(responseText, {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }),
  });

  await assert.rejects(
    () => client.quoteFees({ payload }, {
      canonicalAuth: {
        accountId: authority,
        privateKey: Buffer.alloc(32, 21),
      },
    }),
    /duplicate object key/u,
  );
});

test("quoteFees hard-rejects a 65,537-byte non-success body", async () => {
  const authority = AccountAddress.parseEncoded(VALID_ACCOUNT_ID).address.toI105(369);
  const payload = {
    authority,
    fee_payment: {
      payer: "authority",
      value: { charge_limits: [], gas_limit: null },
    },
  };
  const client = new ToriiClient("https://example.test", {
    fetchImpl: async () => new Response(Buffer.alloc(65_537, 0x20), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    }),
  });

  await assert.rejects(
    () => client.quoteFees({ payload }, {
      canonicalAuth: {
        accountId: authority,
        privateKey: Buffer.alloc(32, 22),
      },
    }),
    /fee quote error response exceeds its 65536-byte size bound/u,
  );
});

test("quoteFees binds sponsored decisions and exact aggregate capacities", async () => {
  const authority = AccountAddress.parseEncoded(VALID_ACCOUNT_ID).address.toI105(369);
  const assetA = "61CtjvNd9T3THAR65GsMVHr82Bjc";
  const assetB = "66owaQmAQMuHxPzxUN3bqZ6FJfDa";
  const programId = { sponsor: authority, name: "wallet_fx" };
  const payload = {
    authority,
    fee_payment: {
      payer: "sponsor",
      value: {
        program_id: programId,
        program_revision: 7,
        charge_limits: [],
        gas_limit: 50,
      },
    },
  };
  const quote = {
    intent: {
      payer: "sponsor",
      value: {
        program_id: programId,
        program_revision: 7,
        charge_limits: [
          {
            kind: { kind: "nexus", value: null },
            asset_definition_id: assetA,
            max_amount: "1.25",
          },
          {
            kind: { kind: "pipeline_gas", value: null },
            asset_definition_id: assetB,
            max_amount: "2.5",
          },
        ],
        gas_limit: 50,
      },
    },
    observation: {
      ledger_time_ms: 100,
      next_block_height: 9,
      route_dataspace_id: 0,
    },
    components: [],
    capacities: [
      {
        asset_definition_id: assetA,
        vault_balance: "2",
        reserve_floor: "0.75",
        block_remaining: "1.25",
        program_epoch_remaining: "1.25",
        beneficiary_epoch_remaining: "1.25",
      },
      {
        asset_definition_id: assetB,
        vault_balance: "4",
        reserve_floor: "1.5",
        block_remaining: "2.5",
        program_epoch_remaining: "2.5",
        beneficiary_epoch_remaining: "2.5",
      },
    ],
    decision: {
      status: "accepted",
      value: {
        debit_source: { kind: "sponsor_program", value: programId },
        program_revision: 7,
      },
    },
  };
  quote.components = quote.intent.value.charge_limits.map((limit) => ({ ...limit }));
  const canonicalAuth = {
    accountId: authority,
    privateKey: Buffer.alloc(32, 16),
  };
  const requestQuote = async (response) => {
    const client = new ToriiClient("https://example.test", {
      fetchImpl: async () => jsonResponse(200, response),
    });
    return client.quoteFees({ payload }, { canonicalAuth });
  };
  const clone = (value) => JSON.parse(JSON.stringify(value));

  assert.deepEqual(await requestQuote(quote), quote);
  const alternateSponsorDisplay = AccountAddress.parseEncoded(authority)
    .address.toI105(753);
  const alternateDisplayQuote = clone(quote);
  alternateDisplayQuote.intent.value.program_id.sponsor = alternateSponsorDisplay;
  alternateDisplayQuote.decision.value.debit_source.value.sponsor = alternateSponsorDisplay;
  assert.deepEqual(await requestQuote(alternateDisplayQuote), alternateDisplayQuote);

  const mutations = [
    ["changed payer", (value) => { value.intent = { payer: "authority", value: { charge_limits: value.intent.value.charge_limits, gas_limit: 50 } }; }, /payer, sponsor revision, or gas bound/u],
    ["changed sponsor", (value) => { value.intent.value.program_id.name = "other"; }, /payer, sponsor revision, or gas bound/u],
    ["changed intent revision", (value) => { value.intent.value.program_revision = 8; }, /payer, sponsor revision, or gas bound/u],
    ["changed gas bound", (value) => { value.intent.value.gas_limit = 51; }, /payer, sponsor revision, or gas bound/u],
    ["zero height", (value) => { value.observation.next_block_height = 0; }, /next_block_height/u],
    ["changed component", (value) => { value.components[0].max_amount = "1.24"; }, /components differ/u],
    ["changed decision revision", (value) => { value.decision.value.program_revision = 8; }, /inconsistent with sponsor payment/u],
    ["missing capacities", (value) => { value.capacities = []; }, /empty exactly when sponsored components/u],
    ["duplicate capacity", (value) => { value.capacities[1].asset_definition_id = assetA; }, /canonical asset order/u],
    ["unsorted capacities", (value) => { value.capacities.reverse(); }, /canonical asset order/u],
    ["unrelated capacity", (value) => { value.capacities[1].asset_definition_id = "62Fk4FPcMuLvW5QjDGNF2a4jAmjM"; }, /canonical asset order/u],
    ["short vault", (value) => { value.capacities[0].vault_balance = "1.99"; }, /vault_balance/u],
    ["short block window", (value) => { value.capacities[0].block_remaining = "1.24"; }, /block_remaining/u],
    ["short program window", (value) => { value.capacities[0].program_epoch_remaining = "1.24"; }, /program_epoch_remaining/u],
    ["short beneficiary window", (value) => { value.capacities[0].beneficiary_epoch_remaining = "1.24"; }, /beneficiary_epoch_remaining/u],
    ["missing gas slot", (value) => { delete value.intent.value.gas_limit; }, /missing required fields: gas_limit/u],
    ["missing route slot", (value) => { delete value.observation.route_dataspace_id; }, /missing required fields: route_dataspace_id/u],
    ["missing decision revision slot", (value) => { delete value.decision.value.program_revision; }, /missing required fields: program_revision/u],
    ["legacy response field", (value) => { value.legacy_quote = true; }, /unsupported fields: legacy_quote/u],
    ["legacy nested field", (value) => { value.decision.value.legacy_revision = 7; }, /unsupported fields: legacy_revision/u],
  ];
  for (const [label, mutate, pattern] of mutations) {
    const changed = clone(quote);
    mutate(changed);
    await assert.rejects(requestQuote(changed), pattern, label);
  }
});

test("quoteFees uses exact decimal arithmetic for shared assets and accepts fee-free sponsors", async () => {
  const authority = AccountAddress.parseEncoded(VALID_ACCOUNT_ID).address.toI105(369);
  const assetDefinitionId = "66owaQmAQMuHxPzxUN3bqZ6FJfDa";
  const programId = { sponsor: authority, name: "shared" };
  const payload = {
    authority,
    fee_payment: {
      payer: "sponsor",
      value: {
        program_id: programId,
        program_revision: 3,
        charge_limits: [],
        gas_limit: null,
      },
    },
  };
  const quote = {
    intent: {
      payer: "sponsor",
      value: {
        program_id: programId,
        program_revision: 3,
        charge_limits: [
          {
            kind: { kind: "nexus", value: null },
            asset_definition_id: assetDefinitionId,
            max_amount: "0.1",
          },
          {
            kind: { kind: "pipeline_gas", value: null },
            asset_definition_id: assetDefinitionId,
            max_amount: "0.2",
          },
        ],
        gas_limit: null,
      },
    },
    observation: {
      ledger_time_ms: 1,
      next_block_height: 1,
      route_dataspace_id: 0,
    },
    components: [],
    capacities: [{
      asset_definition_id: assetDefinitionId,
      vault_balance: "0.4",
      reserve_floor: "0.1",
      block_remaining: "0.3",
      program_epoch_remaining: "0.3",
      beneficiary_epoch_remaining: "0.3",
    }],
    decision: {
      status: "accepted",
      value: {
        debit_source: { kind: "sponsor_program", value: programId },
        program_revision: 3,
      },
    },
  };
  quote.components = quote.intent.value.charge_limits.map((limit) => ({ ...limit }));
  const canonicalAuth = {
    accountId: authority,
    privateKey: Buffer.alloc(32, 17),
  };
  const requestQuote = async (response) => {
    const client = new ToriiClient("https://example.test", {
      fetchImpl: async () => jsonResponse(200, response),
    });
    return client.quoteFees({ payload }, { canonicalAuth });
  };

  assert.deepEqual(await requestQuote(quote), quote);
  const short = JSON.parse(JSON.stringify(quote));
  short.capacities[0].block_remaining = "0.2999999999999999999999999999";
  await assert.rejects(requestQuote(short), /block_remaining/u);

  const maximum = (1n << 511n) - 1n;
  const maximumText = maximum.toString();
  const scaleOneMaximum = `${maximumText.slice(0, -1)}.${maximumText.slice(-1)}`;
  const normalizedSum = ((maximum + 3n) / 10n).toString();
  const normalizedExtreme = JSON.parse(JSON.stringify(quote));
  normalizedExtreme.intent.value.charge_limits[0].max_amount = scaleOneMaximum;
  normalizedExtreme.intent.value.charge_limits[1].max_amount = "0.3";
  normalizedExtreme.components = normalizedExtreme.intent.value.charge_limits.map(
    (limit) => ({ ...limit }),
  );
  Object.assign(normalizedExtreme.capacities[0], {
    vault_balance: normalizedSum,
    reserve_floor: "0",
    block_remaining: normalizedSum,
    program_epoch_remaining: normalizedSum,
    beneficiary_epoch_remaining: normalizedSum,
  });
  assert.deepEqual(await requestQuote(normalizedExtreme), normalizedExtreme);

  const scaleTwentyEightMaximum = `${maximumText.slice(0, -28)}.${maximumText.slice(-28)}`;
  const sufficientExtremeScale = JSON.parse(JSON.stringify(quote));
  sufficientExtremeScale.intent.value.charge_limits = [
    {
      ...sufficientExtremeScale.intent.value.charge_limits[0],
      max_amount: "1",
    },
  ];
  sufficientExtremeScale.components = sufficientExtremeScale.intent.value.charge_limits.map(
    (limit) => ({ ...limit }),
  );
  Object.assign(sufficientExtremeScale.capacities[0], {
    vault_balance: scaleTwentyEightMaximum,
    reserve_floor: "0",
    block_remaining: scaleTwentyEightMaximum,
    program_epoch_remaining: scaleTwentyEightMaximum,
    beneficiary_epoch_remaining: scaleTwentyEightMaximum,
  });
  assert.deepEqual(await requestQuote(sufficientExtremeScale), sufficientExtremeScale);

  const insufficientExtreme = JSON.parse(JSON.stringify(quote));
  insufficientExtreme.intent.value.charge_limits = [
    {
      ...insufficientExtreme.intent.value.charge_limits[0],
      max_amount: maximumText,
    },
  ];
  insufficientExtreme.components = insufficientExtreme.intent.value.charge_limits.map(
    (limit) => ({ ...limit }),
  );
  Object.assign(insufficientExtreme.capacities[0], {
    vault_balance: maximumText,
    reserve_floor: "0",
    block_remaining: scaleTwentyEightMaximum,
    program_epoch_remaining: maximumText,
    beneficiary_epoch_remaining: maximumText,
  });
  await assert.rejects(requestQuote(insufficientExtreme), /block_remaining/u);

  const trailingZero = JSON.parse(JSON.stringify(quote));
  trailingZero.capacities[0].block_remaining = "0.30";
  await assert.rejects(requestQuote(trailingZero), /canonical/u);

  const feeFree = JSON.parse(JSON.stringify(quote));
  feeFree.intent.value.charge_limits = [];
  feeFree.components = [];
  feeFree.capacities = [];
  assert.deepEqual(await requestQuote(feeFree), feeFree);
});

test("quoteFees binds authority decisions and forbids authority capacities", async () => {
  const authority = AccountAddress.parseEncoded(VALID_ACCOUNT_ID).address.toI105(369);
  const payload = {
    authority,
    fee_payment: {
      payer: "authority",
      value: { charge_limits: [], gas_limit: null },
    },
  };
  const quote = {
    intent: payload.fee_payment,
    observation: {
      ledger_time_ms: 1,
      next_block_height: 1,
      route_dataspace_id: 0,
    },
    components: [],
    capacities: [],
    decision: {
      status: "accepted",
      value: {
        debit_source: { kind: "account", value: authority },
        program_revision: null,
      },
    },
  };
  const canonicalAuth = {
    accountId: authority,
    privateKey: Buffer.alloc(32, 18),
  };
  const requestQuote = async (response) => {
    const client = new ToriiClient("https://example.test", {
      fetchImpl: async () => jsonResponse(200, response),
    });
    return client.quoteFees({ payload }, { canonicalAuth });
  };

  assert.deepEqual(await requestQuote(quote), quote);
  const wrongAccount = JSON.parse(JSON.stringify(quote));
  wrongAccount.decision.value.debit_source.value = ALT_ACCOUNT_ID;
  await assert.rejects(requestQuote(wrongAccount), /inconsistent with authority payment/u);

  const wrongRevision = JSON.parse(JSON.stringify(quote));
  wrongRevision.decision.value.program_revision = 1;
  await assert.rejects(requestQuote(wrongRevision), /inconsistent with authority payment/u);

  const withCapacity = JSON.parse(JSON.stringify(quote));
  withCapacity.capacities.push({
    asset_definition_id: "66owaQmAQMuHxPzxUN3bqZ6FJfDa",
    vault_balance: "0",
    reserve_floor: "0",
    block_remaining: "0",
    program_epoch_remaining: "0",
    beneficiary_epoch_remaining: "0",
  });
  await assert.rejects(requestQuote(withCapacity), /empty for authority payment/u);
});

test("quoteFees requires canonical account authentication before sending", async () => {
  let fetchCalls = 0;
  const client = new ToriiClient("https://example.test", {
    fetchImpl: async () => {
      fetchCalls += 1;
      return jsonResponse(200, {});
    },
  });
  await assert.rejects(() => client.quoteFees({ authority: VALID_ACCOUNT_ID }), /canonicalAuth is required/);
  assert.equal(fetchCalls, 0);

  await assert.rejects(
    () => client.quoteFees(
      {
        authority: VALID_ACCOUNT_ID,
        fee_payment: {
          payer: "authority",
          value: { charge_limits: [], gas_limit: null },
        },
      },
      {
        canonicalAuth: {
          accountId: ALT_ACCOUNT_ID,
          privateKey: Buffer.alloc(32, 15),
        },
      },
    ),
    /must identify the payload authority/i,
  );
  assert.equal(fetchCalls, 0);

  await assert.rejects(
    () => client.quoteFees(
      {
        authority: VALID_ACCOUNT_ID,
        fee_payment: {
          payer: "authority",
          value: { charge_limits: [] },
        },
      },
      {
        canonicalAuth: {
          accountId: VALID_ACCOUNT_ID,
          privateKey: Buffer.alloc(32, 16),
        },
      },
    ),
    /missing required fields: gas_limit/u,
  );
  assert.equal(fetchCalls, 0);
});
