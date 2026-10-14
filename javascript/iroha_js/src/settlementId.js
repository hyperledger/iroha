// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Owner-qualified native settlement identifiers.
 *
 * A native `SettlementId` is the closed JSON pair `{ owner, reference }`: `owner`
 * is the participating debit owner whose namespace consumes the business
 * `reference`, a canonical Iroha `Name`. Bare references and extra fields have
 * no fallback.
 */

import { assertCanonicalIrohaName, assertExactFields } from "./instructionBuilderPrimitives.js";
import { normalizeAccountId } from "./normalizers.js";
import { createValidationError, ValidationErrorCode } from "./validationError.js";

/**
 * Normalize an owner-qualified `SettlementId` to its exact native JSON object.
 * @param {{ owner: string, reference: string }} value
 * @param {string} name
 * @returns {{ owner: string, reference: string }}
 */
export function normalizeSettlementId(value, name) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)
  ) {
    throw createValidationError(
      ValidationErrorCode.INVALID_OBJECT,
      `${name} must be a { owner, reference } settlement id`,
      name,
    );
  }
  assertExactFields(value, ["owner", "reference"], name);
  return {
    owner: normalizeAccountId(value.owner, `${name}.owner`),
    reference: assertCanonicalIrohaName(value.reference, `${name}.reference`),
  };
}
