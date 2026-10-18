// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

import { computeHashLiteralCrc } from "./hashLiteralCrc.js";

/** Read durable explorer diagnostics only when the exact requested hash is rejected. */
export async function readExplorerTransactionRejection(load, hashHex) {
  const record = await load();
  const body = hashHex.toUpperCase();
  const expectedHash = `hash:${body}#${computeHashLiteralCrc("hash", body)}`;
  if (record?.hash !== expectedHash || record.status !== "Rejected") return null;
  const message = record.rejection_reason?.message;
  if (typeof message !== "string" || message.trim().length === 0 || message.length > 16_384) return null;
  const block = record.block;
  const blockHeight = (typeof block === "bigint" && block > 0n) ||
    (Number.isSafeInteger(block) && block > 0) ? block : null;
  return { rejectionReason: message, blockHeight };
}

/**
 * Subscribe before submission so ephemeral rejection details are not missed.
 * This observer is diagnostic only: events never establish transaction finality.
 */
export async function observeTransactionRejection(openStream, hashHex, signal) {
  const controller = new AbortController();
  const abort = () => controller.abort(signal.reason);
  if (signal?.aborted) abort();
  else signal?.addEventListener("abort", abort, { once: true });
  let ready;
  let fail;
  const opened = new Promise((resolve, reject) => { ready = resolve; fail = reject; });
  let details = null;
  let received;
  const rejection = new Promise((resolve) => { received = resolve; });
  const task = (async () => {
    try {
      for await (const frame of openStream(controller.signal, ready)) {
        const event = frame.data;
        if (frame.event === "stream_error") throw new Error("transaction rejection event stream failed");
        if (event?.category === "Pipeline" && event.event === "Transaction" &&
            event.hash === hashHex && event.status === "Rejected" &&
            typeof event.rejection_code === "string" && typeof event.rejection_reason === "string") {
          details = {
            rejectionCode: event.rejection_code,
            rejectionReason: event.rejection_reason,
            blockHeight: event.block_height ?? null,
          };
          received();
          break;
        }
      }
      fail(new Error("transaction rejection event stream closed before opening"));
    } catch (error) {
      fail(error);
    } finally {
      received();
    }
  })();
  const close = async () => {
    controller.abort();
    signal?.removeEventListener("abort", abort);
    await task;
  };
  try {
    await opened;
  } catch (error) {
    await close();
    throw error;
  }
  return {
    async read() {
      // State may resolve a rejection immediately before its event is delivered.
      let timer;
      try {
        await Promise.race([rejection, new Promise((resolve) => { timer = setTimeout(resolve, 1_000); })]);
        return details;
      } finally {
        clearTimeout(timer);
      }
    },
    close,
  };
}
