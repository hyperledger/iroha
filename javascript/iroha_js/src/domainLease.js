// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Domain leasing through declarative alias setup (`EnsureAlias`).
 *
 * After genesis a domain is created only by a paid SNS domain lease: one
 * `EnsureAlias` with a `domain` intent charges the quoted rent to the
 * transaction authority, registers the `Domain` owned by the intent owner and
 * grants the owner the domain-scoped account-alias permissions. Asset-definition
 * aliases additionally need `CanManageAssetDefinitionAlias` for the domain
 * (see `buildGrantAssetDefinitionAliasScopeInstruction`).
 */

import { AccountAddress } from "./address.js";
import { canonicalizeDomainId } from "./domainId.js";
import { normalizeAccountId } from "./normalizers.js";
import { defaultNativeRuntime, resolveNativeRuntimeBinding } from "./nativeRuntime.js";

/** Native SNS suffix id of the domain namespace (`DOMAIN_NAME_SUFFIX_ID`). */
export const SNS_DOMAIN_SUFFIX_ID = 0x1002;
const DEFAULT_QUOTE_VALIDITY_MS = 5 * 60 * 1000;
const ENSURE_ALIAS_WIRE_ID = "iroha.alias.ensure";

function decimalTimes(amount, factor, context) {
  const match = /^(0|[1-9]\d*)(?:\.(\d+))?$/u.exec(String(amount));
  if (!match) {
    throw new TypeError(`${context} must be a canonical decimal quantity`);
  }
  const fraction = match[2] ?? "";
  const digits = (BigInt(match[1] + fraction) * BigInt(factor))
    .toString()
    .padStart(fraction.length + 1, "0");
  const whole = digits.slice(0, digits.length - fraction.length);
  const decimals = digits.slice(digits.length - fraction.length).replace(/0+$/u, "");
  return decimals.length === 0 ? whole : `${whole}.${decimals}`;
}

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function leaseCap(policy, domain, years) {
  for (const tier of policy.pricing) {
    let pattern;
    try {
      pattern = new RegExp(tier.labelRegex, "u");
    } catch {
      throw new Error(
        `SNS pricing tier ${tier.tierId} regex is not portable to JavaScript; pass request.maxAmount`,
      );
    }
    if (pattern.test(domain)) {
      if (years < tier.minDurationYears || years > tier.maxDurationYears) {
        throw new RangeError(
          `years must be within ${tier.minDurationYears}..=${tier.maxDurationYears} for pricing tier ${tier.tierId}`,
        );
      }
      return decimalTimes(tier.basePrice.amount, years, "SNS base price");
    }
  }
  throw new Error(`domain ${domain} matches no SNS domain pricing tier`);
}

/**
 * Plan a paid domain lease and return the exact instructions to submit.
 *
 * Reads the domain SNS policy, builds one `EnsureAlias` domain intent whose
 * quote guard pins the policy version, payment asset, a price cap (the matching
 * tier's base price times `years`, or `request.maxAmount`) and a deadline, asks
 * Torii's read-only planner (`POST /v1/aliases/setup/plan`) to quote it, and
 * converts each planned Norito frame into strict instruction JSON after an
 * exact decode/re-frame check. The canonical-auth account is the plan authority
 * and lease payer; sign the transaction with that account, keep its TTL within
 * `validUntilMs`, and fund it with at least `totalsByAsset`.
 *
 * @param {import("./toriiClient.js").ToriiClient} torii client with a LocalSigningContext
 * @param {{ owner: string, domain: string, years: number, dataspaceId?: number, maxAmount?: string, quoteValidityMs?: number }} request
 * @param {{ canonicalAuth: { accountId: string, privateKey: ArrayBufferView | ArrayBuffer }, signal?: AbortSignal }} options
 */
export async function planDomainLease(torii, request, options = {}) {
  if (!torii || typeof torii.planAliasSetup !== "function" || typeof torii.getSnsPolicy !== "function") {
    throw new TypeError("torii must be a ToriiClient");
  }
  if (request === null || typeof request !== "object" || Array.isArray(request)) {
    throw new TypeError("planDomainLease request must be an object");
  }
  const allowed = new Set(["owner", "domain", "years", "dataspaceId", "maxAmount", "quoteValidityMs"]);
  for (const key of Object.keys(request)) {
    if (!allowed.has(key)) throw new TypeError(`planDomainLease request.${key} is not supported`);
  }
  const owner = normalizeAccountId(request.owner, "planDomainLease.owner");
  const domain = canonicalizeDomainId(request.domain, "planDomainLease.domain");
  const years = request.years;
  if (!Number.isInteger(years) || years < 1 || years > 255) {
    throw new RangeError("planDomainLease.years must be an integer in 1..=255");
  }
  const dataspace = domain.split(".")[1];
  const dataspaceId = request.dataspaceId ?? (dataspace === "universal" ? 0 : undefined);
  if (!Number.isSafeInteger(dataspaceId) || dataspaceId < 0) {
    throw new TypeError(
      "planDomainLease.dataspaceId is required for a domain outside the universal data space",
    );
  }
  const quoteValidityMs = request.quoteValidityMs ?? DEFAULT_QUOTE_VALIDITY_MS;
  if (!Number.isSafeInteger(quoteValidityMs) || quoteValidityMs <= 0) {
    throw new RangeError("planDomainLease.quoteValidityMs must be a positive safe integer");
  }
  const { canonicalAuth, signal } = options;
  const policy = await torii.getSnsPolicy(SNS_DOMAIN_SUFFIX_ID, { signal });
  if (policy.status !== "Active") {
    throw new Error(`SNS domain policy is ${policy.status}`);
  }
  if (years < policy.minTermYears || years > policy.maxTermYears) {
    throw new RangeError(
      `planDomainLease.years must be within ${policy.minTermYears}..=${policy.maxTermYears}`,
    );
  }
  const maxAmount = request.maxAmount === undefined
    ? leaseCap(policy, domain, years)
    : decimalTimes(request.maxAmount, 1, "planDomainLease.maxAmount");
  const ensure = {
    intent: {
      kind: "domain",
      intent: { domain: { canonical_name: domain, dataspace_id: dataspaceId }, owner },
    },
    acquisition: { term_years: years, pricing_class_hint: null },
    quote_guard: {
      expected_policy_version: policy.policyVersion,
      expected_payment_asset: policy.paymentAssetId,
      max_amount: maxAmount,
      valid_until_ms: Date.now() + quoteValidityMs,
    },
  };
  const plan = await torii.planAliasSetup(
    { schema_version: 1, intents: [ensure] },
    { canonicalAuth, signal },
  );
  const body = plan.body;
  if (Array.isArray(body.blockers) && body.blockers.length > 0) {
    throw new Error(`alias setup plan is blocked: ${JSON.stringify(body.blockers)}`);
  }
  if (!Array.isArray(body.resources) || body.resources.length !== 1) {
    throw new Error("alias setup plan must describe exactly the requested domain");
  }
  const [resource] = body.resources;
  const disposition = resource?.disposition?.kind;
  const { chainDiscriminant } = AccountAddress.parseEncoded(owner);
  const native = resolveNativeRuntimeBinding(defaultNativeRuntime);
  const instructions = (Array.isArray(body.instructions) ? body.instructions : []).map(
    (frame, index) => {
      if (frame?.wire_id !== ENSURE_ALIAS_WIRE_ID || !Array.isArray(frame.framed_payload)) {
        throw new Error(`alias setup plan instruction ${index} is not an EnsureAlias frame`);
      }
      const instruction = JSON.parse(
        native.instructionJsonFromWirePair(
          frame.wire_id,
          Uint8Array.from(frame.framed_payload),
          chainDiscriminant,
        ),
      );
      if (stableJson(instruction.EnsureAlias) !== stableJson(ensure)) {
        throw new Error("alias setup plan instruction differs from the requested domain lease");
      }
      return instruction;
    },
  );
  if (disposition === "create" && instructions.length !== 1) {
    throw new Error("a domain lease plan must contain exactly one EnsureAlias instruction");
  }
  return {
    instructions,
    disposition,
    quote: resource.quote ?? null,
    totalsByAsset: body.totals_by_asset ?? [],
    authority: body.authority,
    validUntilMs: body.valid_until_ms,
    planHash: plan.plan_hash,
    plan,
  };
}
