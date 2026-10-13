import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { ToriiClient } from "../src/toriiClient.js";

const repoListFixture = JSON.parse(
  readFileSync(new URL("./fixtures/torii_responses.json", import.meta.url), "utf8"),
).repo.list;

test("repo agreement rows expose lifecycle and custody fields under their query names", async () => {
  let requested;
  const client = new ToriiClient("https://localhost:8080", {
    fetchImpl: async (url, init) => {
      requested = { url: new URL(url), body: init.body };
      return new Response(JSON.stringify({ items: repoListFixture.items, next_cursor: null }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
  });

  const page = await client.repoAgreements.list({ filter: 'status = "active"', limit: 2 });
  assert.equal(requested.url.pathname, "/v1/repo/agreements/query");
  assert.equal(requested.body, '{"filter":"status = \\"active\\"","limit":2}');
  const [agreement] = page.items;
  assert.match(agreement.cash_source, /^7EAD8EFYUx1aVKZPUU1fyKvr8dF1@/);
  assert.match(agreement.collateral_custody_asset, /^4fEiy2n5VMFVfi6BzDJge519zAzg@/);
  assert.equal(agreement.settlement_timestamp_ms, null);
  assert.equal(agreement.status, "active");
  assert.equal(agreement.governance.allow_early_repayment, false);
  assert.equal(page.nextCursor, null);
});
