#!/usr/bin/env node
/**
 * ISO 20022 message builder + submission helper.
 *
 * Demonstrates how to construct pacs.008 or pacs.009 payloads via the SDK
 * builder helpers so Node callers do not need to hand-write XML strings. The
 * template requires a payer-retained UETR and exact native settlement terms;
 * envelope fields can come from environment variables or a JSON config file.
 *
 * Usage:
 *   ISO_BUILDER_CONFIG=/path/to/retained-payment.json \
 *     node ./recipes/iso_bridge_builder.mjs
 *
 * Provide ISO_BUILDER_CONFIG=/path/to/options.json to merge structured fields
 * (shape documented in BuildPacs008Options / BuildPacs009Options).
 */

import { readFile } from "node:fs/promises";
import { buildPacs008Message, buildPacs009Message } from "../dist/index.js";

import { nativeIntentFromEnvironment, parseConfiguredNativeIntent, createIsoOperatorClient } from "./iso_bridge_context.mjs";

const TORII_URL = process.env.TORII_URL ?? "http://localhost:8080";
const ISO_KIND = (process.env.ISO_KIND ?? "pacs.008").toLowerCase();
const ISO_CONFIG_PATH = process.env.ISO_BUILDER_CONFIG;
const ISO_SUBMIT = process.env.ISO_SUBMIT === "1";
const ISO_DRY_RUN = process.env.ISO_DRY_RUN === "1";
const ISO_RESOLVE_ON_ACCEPTED = process.env.ISO_RESOLVE_ON_ACCEPTED === "1";

function env(name) {
  const value = process.env[name];
  return value && value.trim().length > 0 ? value.trim() : undefined;
}

function parseJsonEnv(name) {
  const raw = env(name);
  if (!raw) {
    return undefined;
  }
  try {
    return JSON.parse(raw);
  } catch (error) {
    throw new Error(`${name} must contain valid JSON`, { cause: error });
  }
}

function partyFromEnv(prefix) {
  const name = env(`${prefix}_NAME`);
  if (!name) {
    return undefined;
  }
  return {
    name,
    lei: env(`${prefix}_LEI`),
    identifier: env(`${prefix}_ID`),
    identifierScheme: env(`${prefix}_ID_SCHEME`),
  };
}

function agentFromEnv(prefix) {
  const bic = env(`${prefix}_BIC`);
  if (!bic) {
    return undefined;
  }
  return {
    bic,
    lei: env(`${prefix}_LEI`),
  };
}

function baseOptions() {
  const now = Date.now();
  return {
    ...nativeIntentFromEnvironment(),
    messageId: env("ISO_MESSAGE_ID") ?? `iso-builder-${now}`,
    creationDateTime: env("ISO_CREATION_TIME") ?? new Date(now).toISOString(),
    instructionId: env("ISO_INSTRUCTION_ID") ?? `instr-${now}`,
    endToEndId: env("ISO_END_TO_END_ID"),
    transactionId: env("ISO_TRANSACTION_ID"),
    businessMessageId: env("ISO_BUSINESS_MESSAGE_ID"),
    messageDefinitionId: env("ISO_MESSAGE_DEFINITION_ID"),
    settlementDate: env("ISO_SETTLEMENT_DATE"),
    amount: {
      currency: env("ISO_CURRENCY") ?? "EUR",
      value: env("ISO_AMOUNT") ?? "100.00",
    },
    instigatingAgent: {
      bic: env("ISO_INSTG_BIC") ?? "DEUTDEFF",
      lei: env("ISO_INSTG_LEI"),
    },
    instructedAgent: {
      bic: env("ISO_INSTD_BIC") ?? "COBADEFF",
      lei: env("ISO_INSTD_LEI"),
    },
    debtorAgent: agentFromEnv("ISO_DEBTOR_AGENT"),
    creditorAgent: agentFromEnv("ISO_CREDITOR_AGENT"),
    debtor: partyFromEnv("ISO_DEBTOR"),
    creditor: partyFromEnv("ISO_CREDITOR"),
    debtorAccount: env("ISO_DEBTOR_IBAN")
      ? { iban: env("ISO_DEBTOR_IBAN") }
      : undefined,
    creditorAccount: env("ISO_CREDITOR_IBAN")
      ? { iban: env("ISO_CREDITOR_IBAN") }
      : env("ISO_CREDITOR_OTHER")
        ? { otherId: env("ISO_CREDITOR_OTHER") }
        : undefined,
    purposeCode: env("ISO_PURPOSE"),
    supplementaryData: parseJsonEnv("ISO_SUPPLEMENTARY_JSON"),
  };
}

async function loadConfigOverrides() {
  if (!ISO_CONFIG_PATH) {
    return {};
  }
  const data = await readFile(ISO_CONFIG_PATH, "utf-8");
  try {
    return JSON.parse(data);
  } catch (error) {
    throw new Error(`Failed to parse ISO config at ${ISO_CONFIG_PATH}`, { cause: error });
  }
}

function mergeOptions(base, overrides) {
  const merged = { ...base, ...overrides };
  if (overrides.nexusSettlement) {
    merged.nexusSettlement = { ...base.nexusSettlement, ...overrides.nexusSettlement };
  }
  if (overrides.amount) {
    merged.amount = { ...base.amount, ...overrides.amount };
  }
  if (overrides.instigatingAgent) {
    merged.instigatingAgent = { ...base.instigatingAgent, ...overrides.instigatingAgent };
  }
  if (overrides.instructedAgent) {
    merged.instructedAgent = { ...base.instructedAgent, ...overrides.instructedAgent };
  }
  if (overrides.debtorAgent) {
    merged.debtorAgent = { ...(base.debtorAgent ?? {}), ...overrides.debtorAgent };
  }
  if (overrides.creditorAgent) {
    merged.creditorAgent = { ...(base.creditorAgent ?? {}), ...overrides.creditorAgent };
  }
  if (overrides.debtor) {
    merged.debtor = { ...(base.debtor ?? {}), ...overrides.debtor };
  }
  if (overrides.creditor) {
    merged.creditor = { ...(base.creditor ?? {}), ...overrides.creditor };
  }
  if (overrides.debtorAccount) {
    merged.debtorAccount = { ...overrides.debtorAccount };
  }
  if (overrides.creditorAccount) {
    merged.creditorAccount = { ...overrides.creditorAccount };
  }
  if (overrides.supplementaryData) {
    merged.supplementaryData = overrides.supplementaryData;
  }
  return merged;
}

async function main() {
  const overrides = await loadConfigOverrides();
  if (!["pacs.008", "pacs.009"].includes(ISO_KIND)) {
    throw new TypeError("ISO_KIND must be pacs.008 or pacs.009");
  }
  const options = parseConfiguredNativeIntent(mergeOptions(baseOptions(), overrides));
  const xml =
    ISO_KIND === "pacs.009" ? buildPacs009Message(options) : buildPacs008Message(options);

  if (!ISO_SUBMIT || ISO_DRY_RUN) {
    console.log(xml);
    if (!ISO_SUBMIT || ISO_DRY_RUN) {
      return;
    }
  }

  const waitOptions = {
    maxAttempts: Number(process.env.ISO_POLL_ATTEMPTS ?? 15),
    pollIntervalMs: Number(process.env.ISO_POLL_INTERVAL_MS ?? 2_000),
    resolveOnAcceptedWithoutTransaction: ISO_RESOLVE_ON_ACCEPTED,
    onPoll: ({ attempt, status }) => {
      const label = status?.status ?? "unknown";
      const hash = status?.transaction_hash ?? "<pending>";
      process.stdout.write(`[iso-builder] attempt ${attempt}: ${label} tx=${hash}\n`);
    },
  };

  const client = await createIsoOperatorClient(TORII_URL, options.nexusSettlement.networkId);
  const usePacs009 = ISO_KIND === "pacs.009";
  const response = usePacs009
    ? await client.submitIsoPacs009AndWait(xml, { wait: waitOptions })
    : await client.submitIsoPacs008AndWait(xml, { wait: waitOptions });
  // This observation is not an independently verified monetary receipt.
  const txHash = response.transaction_hash ?? "<pending>";
  console.log(
    `[iso-builder] ${ISO_KIND} ${response.message_id} node-reported status ${
      response.status ?? "unknown"
    } tx=${txHash}`,
  );
}

main().catch((error) => {
  console.error("[iso-builder] failed:", error);
  process.exitCode = 1;
});
