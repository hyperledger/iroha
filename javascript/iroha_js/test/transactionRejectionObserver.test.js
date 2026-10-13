import { test } from "node:test";
import assert from "node:assert/strict";
import { observeTransactionRejection, readExplorerTransactionRejection } from "../src/transactionRejectionObserver.js";

const HASH = "55".repeat(32);
const event = (hash = HASH) => ({ event: null, data: {
  category: "Pipeline", event: "Transaction", hash, status: "Rejected",
  rejection_code: "instruction_execution", rejection_reason: "Instruction execution failed",
  block_height: 41,
} });

test("rejection observer opens before returning and keeps only the requested transaction", async () => {
  let opened = false;
  const observer = await observeTransactionRejection(async function* (_signal, ready) {
    opened = true;
    ready();
    yield event("57".repeat(32));
    yield event();
  }, HASH);
  assert.equal(opened, true);
  assert.deepEqual(await observer.read(), {
    rejectionCode: "instruction_execution", rejectionReason: "Instruction execution failed",
    blockHeight: 41,
  });
  await observer.close();
});

test("rejection observer fails if subscription never opens", async () => {
  await assert.rejects(observeTransactionRejection(async function* () {
    yield { event: "stream_error", data: {} };
  }, HASH), /event stream failed/u);
  await assert.rejects(observeTransactionRejection(async function* () {
    yield { event: null, data: {} };
  }, HASH), /closed before opening/u);
});

test("rejection observer closes an idle subscription and tolerates a lost stream", async () => {
  let closed = false;
  const observer = await observeTransactionRejection(async function* (signal, ready) {
    const aborted = new Promise((resolve) => signal.addEventListener("abort", resolve, { once: true }));
    ready();
    await aborted;
    closed = true;
    yield { event: null, data: {} };
  }, HASH);
  await observer.close();
  assert.equal(closed, true);
  const lost = await observeTransactionRejection(async function* (_signal, ready) {
    ready();
    yield { event: "stream_error", data: {} };
  }, HASH);
  assert.equal(await lost.read(), null);
  await lost.close();
});

test("rejection observer forwards caller cancellation", async () => {
  const controller = new AbortController();
  let observed;
  const observer = await observeTransactionRejection(async function* (signal, ready) {
    const aborted = new Promise((resolve) => signal.addEventListener("abort", resolve, { once: true }));
    ready();
    await aborted;
    observed = signal.reason;
    yield { event: null, data: {} };
  }, HASH, controller.signal);
  controller.abort(new Error("stop"));
  await observer.close();
  assert.equal(observed.message, "stop");
});

test("durable rejection diagnostics bind the exact canonical transaction hash and rejected status", async () => {
  // Captured from the live Taira explorer after a rejected asset-alias registration.
  const hash = "d97231dc46af4206b978dfe8da793f21f96dedd0529717039a73e1d8cd303fff";
  const record = {
    hash: "hash:D97231DC46AF4206B978DFE8DA793F21F96DEDD0529717039A73E1D8CD303FFF#85AC",
    block: 86, status: "Rejected",
    rejection_reason: { message: "Validation failed: invalid asset definition alias" },
  };
  assert.deepEqual(await readExplorerTransactionRejection(async () => record, hash), {
    rejectionReason: record.rejection_reason.message, blockHeight: 86,
  });
  for (const invalid of [null, { ...record, hash: HASH }, { ...record, hash: record.hash.toLowerCase() },
    { ...record, status: "Applied" }, { ...record, rejection_reason: null },
    { ...record, rejection_reason: { message: " " } }]) {
    assert.equal(await readExplorerTransactionRejection(async () => invalid, hash), null);
  }
  assert.equal(await readExplorerTransactionRejection(async () => record, HASH), null);
  await assert.rejects(readExplorerTransactionRejection(async () => { throw new Error("404"); }, hash), /404/u);
});
