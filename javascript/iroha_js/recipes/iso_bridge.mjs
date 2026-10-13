#!/usr/bin/env node
/**
 * ISO 20022 pacs.008 / pacs.009 submission walkthrough.
 *
 * Demonstrates how to post an ISO 20022 customer or bank payment
 * (pacs.008 / pacs.009) payload to Torii's ISO bridge and poll the resulting status until
 * the node reports a terminal status or a timeout elapses. Status polling does
 * not independently verify monetary settlement.
 *
 * Usage:
 *   TORII_URL=http://localhost:8080 node ./recipes/iso_bridge.mjs
 */
import {
  buildSamplePacs008Message,
  buildSamplePacs009Message,
} from "../dist/index.js";
import { NetworkId } from "../dist/index.js";
import { nativeIntentFromEnvironment, parseConfiguredNativeIntent, createIsoOperatorClient } from "./iso_bridge_context.mjs";

const TORII_URL = process.env.TORII_URL ?? "http://localhost:8080";
const MAX_POLL_ATTEMPTS = Number(process.env.ISO_POLL_ATTEMPTS ?? 12);
const POLL_INTERVAL_MS = Number(process.env.ISO_POLL_INTERVAL_MS ?? 2_000);
const CONTENT_TYPE = process.env.ISO_CONTENT_TYPE?.trim();

const MESSAGE_KIND = (process.env.ISO_MESSAGE_KIND ?? "pacs.008").toLowerCase();
const EXISTING_MESSAGE_ID = process.env.ISO_MESSAGE_ID?.trim();
const RESOLVE_ON_ACCEPTED = process.env.ISO_RESOLVE_ON_ACCEPTED === "1";
const MESSAGE_SUFFIX =
  process.env.ISO_MESSAGE_SUFFIX ?? Math.floor(Date.now() / 1000).toString(16);

if (!["pacs.008", "pacs.009"].includes(MESSAGE_KIND)) {
  console.error("ISO_MESSAGE_KIND must be 'pacs.008' or 'pacs.009'");
  process.exit(1);
}
if (CONTENT_TYPE !== undefined && CONTENT_TYPE.length === 0) {
  console.error("ISO_CONTENT_TYPE must not be empty when provided");
  process.exit(1);
}

async function main() {
  const networkId = NetworkId.parse(process.env.ISO_NETWORK_ID);
  const client = await createIsoOperatorClient(TORII_URL, networkId);
  const waitOptions = {
    maxAttempts: MAX_POLL_ATTEMPTS,
    pollIntervalMs: POLL_INTERVAL_MS,
    resolveOnAcceptedWithoutTransaction: RESOLVE_ON_ACCEPTED,
    onPoll: ({ attempt, status }) => {
      if (!status) {
        console.log(`Attempt ${attempt}: status unavailable (retrying)`);
        return;
      }
      const hash = status.transaction_hash ?? "<pending>";
      console.log(`Attempt ${attempt}: ${status.status ?? "unknown"} tx=${hash}`);
    },
  };

  let finalStatus;
  if (EXISTING_MESSAGE_ID) {
    console.log(`Waiting for ISO message ${EXISTING_MESSAGE_ID}...`);
    finalStatus = await client.waitForIsoMessageStatus(EXISTING_MESSAGE_ID, waitOptions);
  } else {
    const options = parseConfiguredNativeIntent({
      ...nativeIntentFromEnvironment(),
      messageSuffix: MESSAGE_SUFFIX,
    });
    const payload = MESSAGE_KIND === "pacs.009"
      ? buildSamplePacs009Message(options)
      : buildSamplePacs008Message(options);
    console.log(`Submitting ${MESSAGE_KIND} to ${TORII_URL}`);
    const submissionOptions = CONTENT_TYPE
      ? { contentType: CONTENT_TYPE, wait: waitOptions }
      : { wait: waitOptions };
    finalStatus =
      MESSAGE_KIND === "pacs.009"
        ? await client.submitIsoPacs009AndWait(payload, submissionOptions)
        : await client.submitIsoPacs008AndWait(payload, submissionOptions);
  }

  const hash = finalStatus.transaction_hash ?? "<pending>";
  console.log(
    `Node-reported status for ${finalStatus.message_id}: ${finalStatus.status ?? "unknown"} tx=${hash}`,
  );
}

main().catch((error) => {
  console.error("ISO bridge recipe failed:", error);
  process.exitCode = 1;
});
